import os
import sys
import re
import json
import struct
import hashlib
import subprocess
from datetime import datetime
import difflib
import urllib.request

P0 = 0x9E3779B97F4A7C15
P1 = 0x6C62272E07BB0142
P2 = 0x94D049BB133111EB
P3 = 0xBF58476D1CE4E5B9
MASK64 = 0xFFFFFFFFFFFFFFFF

PURGEABLE_META_KEYS = ["name", "icon", "version", "author", "description", "app_version", "sdk_version"]
ALWAYS_UPDATE_KEYS = ["id", "hash", "bithash", "size", "link", "state", "update_date"]

know_authors = {
    "@AlexeiCrystal": "1169951070",
    "@PESSDES_Plugins": "6914257655",
    "@YouRooni": "855890735",
    "@RnPlugins": "855890735",
    "@nonPlugins": "3551573748",
    "@itskotovski": "75671920",
    "@mihailkotovski & @mishabotov": "75671920",
    "@shareui": "400216230",
    "@shareui(@doctashare)": "400216230",
    "@itNotMax - @MaxExteraPlugins": "929185014",
    "@itNotMax": "929185014"
}

def calculate_bithash(data: bytes, seed: int = 0) -> str:
    s0 = (seed ^ P0) & MASK64
    s1 = (seed ^ P1) & MASK64
    s2 = (seed ^ P2) & MASK64
    s3 = (seed ^ P3) & MASK64

    length = len(data)
    blocks = length // 32
    p = 0

    for _ in range(blocks):
        b = data[p : p + 32]
        v0, v1, v2, v3 = struct.unpack("<QQQQ", b)

        a, b_val = (s0 ^ v0) & MASK64, P1
        r = a * b_val
        s0 = ((r >> 64) ^ (r & MASK64)) & MASK64

        a, b_val = (s1 ^ v1) & MASK64, P2
        r = a * b_val
        s1 = ((r >> 64) ^ (r & MASK64)) & MASK64

        a, b_val = (s2 ^ v2) & MASK64, P3
        r = a * b_val
        s2 = ((r >> 64) ^ (r & MASK64)) & MASK64

        a, b_val = (s3 ^ v3) & MASK64, P0
        r = a * b_val
        s3 = ((r >> 64) ^ (r & MASK64)) & MASK64

        p += 32

    rem_data = data[p:]
    rem_len = len(rem_data)
    state = s0 ^ s1 ^ s2 ^ s3

    if rem_len >= 16:
        v0, v1 = struct.unpack("<QQ", rem_data[:16])
        a = (state ^ v0) & MASK64
        r = a * P2
        state = ((r >> 64) ^ (r & MASK64)) & MASK64

        a = (state ^ v1) & MASK64
        r = a * P3
        state = ((r >> 64) ^ (r & MASK64)) & MASK64

        rem_data = rem_data[16:]
        rem_len -= 16

    if rem_len >= 8:
        v0 = struct.unpack("<Q", rem_data[:8])[0]
        a = (state ^ v0) & MASK64
        r = a * P0
        state = ((r >> 64) ^ (r & MASK64)) & MASK64

        rem_data = rem_data[8:]
        rem_len -= 8

    if rem_len >= 4:
        v0 = struct.unpack("<I", rem_data[:4])[0]
        v1 = struct.unpack("<I", rem_data[rem_len - 4 : rem_len])[0]
        state ^= v0 | (v1 << 32)
        state &= MASK64
        r = state * P1
        state = ((r >> 64) ^ (r & MASK64)) & MASK64

        rem_data = rem_data[4:]
        rem_len -= 4

    if rem_len > 0:
        v = (
            rem_data[0]
            | (rem_data[rem_len >> 1] << 8)
            | (rem_data[rem_len - 1] << 16)
        )
        a = (state ^ v) & MASK64
        r = a * P2
        state = ((r >> 64) ^ (r & MASK64)) & MASK64

    t = state
    final_len = (t ^ length) & MASK64

    a = (s0 ^ P0) & MASK64
    b_val = (s1 ^ P1) & MASK64
    r = a * b_val
    m0 = ((r >> 64) ^ (r & MASK64)) & MASK64

    a = (s2 ^ P0) & MASK64
    b_val = (s3 ^ P1) & MASK64
    r = a * b_val
    m1 = ((r >> 64) ^ (r & MASK64)) & MASK64

    h = m0 ^ m1

    a = (h ^ final_len) & MASK64
    r = a * P3
    h = ((r >> 64) ^ (r & MASK64)) & MASK64

    h = (h ^ (h >> 33)) & MASK64
    h = (h * P0) & MASK64
    h = (h ^ (h >> 29)) & MASK64
    h = (h * P2) & MASK64
    h = (h ^ (h >> 32)) & MASK64

    return f"{h:016x}"

def format_size(size_bytes: int) -> str:
    units = ['B', 'KB', 'MB', 'GB']
    val = float(size_bytes)
    for unit in units:
        if val < 1024 or unit == 'GB':
            if unit == 'B':
                return f"{int(val)} B"
            formatted = f"{val:.2f}".rstrip('0').rstrip('.')
            return f"{formatted} {unit}"
        val /= 1024
    return f"{size_bytes} B"

def parse_plugin_content(binary_data: bytes, file_path: str) -> dict:
    try:
        text_content = binary_data.decode("utf-8")
    except UnicodeDecodeError:
        text_content = binary_data.decode("latin-1")

    temp_dict = {}
    temp_dict["has_dex"] = "DexClassLoader" in text_content

    id_match = re.search(r'__id__\s*=\s*["\']([^"\']+)["\']', text_content)
    if not id_match:
        print(f"ERROR: __id__ not found in {file_path}")
        return None

    plugin_id = id_match.group(1)
    temp_dict["id"] = plugin_id

    for key, regex in [
        ("name", r'__name__\s*=\s*["\']([^"\']+)["\']'),
        ("version", r'__version__\s*=\s*["\']([^"\']+)["\']'),
        ("author", r'__author__\s*=\s*["\']([^"\']+)["\']'),
        ("sdk_version", r'__sdk_version__\s*=\s*["\']([^"\']+)["\']'),
        ("icon", r'__icon__\s*=\s*["\']([^"\']+)["\']'),
    ]:
        match = re.search(regex, text_content)
        if match:
            temp_dict[key] = match.group(1)

    desc_match = re.search(r'__description__\s*=\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|["\']([^"\']+)["\'])', text_content, re.DOTALL)
    if desc_match:
        desc_val = next(g for g in desc_match.groups() if g is not None)
        temp_dict["description"] = desc_val

    min_ver_match = re.search(r'__min_version__\s*=\s*["\']([^"\']+)["\']', text_content)
    app_ver_match = re.search(r'__app_version__\s*=\s*["\']([^"\']+)["\']', text_content)

    if app_ver_match:
        temp_dict["app_version"] = app_ver_match.group(1)
    elif min_ver_match:
        temp_dict["app_version"] = f">={min_ver_match.group(1)}"

    sha256_hash = hashlib.sha256(binary_data).hexdigest()
    temp_dict["hash"] = sha256_hash

    bithash_val = calculate_bithash(binary_data)
    temp_dict["bithash"] = bithash_val

    file_size_str = format_size(len(binary_data))
    temp_dict["size"] = file_size_str

    filename = os.path.basename(file_path)
    temp_dict["link"] = f"https://github.com/AlexeiCrystal/extera-plugins/raw/main/plugins/{filename}"

    check_str = f"{filename} {temp_dict.get('name', '')} {temp_dict.get('version', '')}".lower()
    if "beta" in check_str or "бета" in check_str:
        temp_dict["state"] = "beta"
    elif "alpha" in check_str or "альфа" in check_str:
        temp_dict["state"] = "alpha"
    else:
        temp_dict["state"] = "release"

    current_date = datetime.now().strftime("%d.%m.%Y")
    temp_dict["update_date"] = current_date

    return temp_dict

def parse_plugin_file(file_path: str) -> dict:
    if not os.path.exists(file_path):
        return None
    with open(file_path, "rb") as f:
        binary_data = f.read()
    res = parse_plugin_content(binary_data, file_path)
    if res:
        try:
            res["_raw_text"] = binary_data.decode("utf-8")
        except UnicodeDecodeError:
            res["_raw_text"] = binary_data.decode("latin-1")
    return res

def get_deleted_file_content(file_path: str) -> bytes:
    refs = []
    if "GITHUB_BEFORE" in os.environ and os.environ["GITHUB_BEFORE"]:
        refs.append(os.environ["GITHUB_BEFORE"])
    refs.extend(["HEAD~1", "HEAD^", "HEAD"])

    for ref in refs:
        try:
            res = subprocess.run(
                ["git", "show", f"{ref}:{file_path}"],
                capture_output=True,
                check=True
            )
            if res.stdout:
                return res.stdout
        except Exception:
            continue
    return None

def fetch_bytes_for_link(link: str) -> bytes:
    if not link:
        return None
    basename = os.path.basename(link)
    local_path = os.path.join("plugins", basename)

    if os.path.exists(local_path):
        with open(local_path, "rb") as f:
            return f.read()

    b = get_deleted_file_content(local_path)
    if b:
        return b

    try:
        with urllib.request.urlopen(link) as resp:
            return resp.read()
    except Exception:
        return None

def get_plugin_text(link: str) -> str:
    b = fetch_bytes_for_link(link)
    if b:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("latin-1")
    return ""

def calculate_diff(old_text: str, new_text: str):
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    diff = difflib.ndiff(old_lines, new_lines)
    added = 0
    removed = 0
    for line in diff:
        if line.startswith('+ '):
            added += 1
        elif line.startswith('- '):
            removed += 1
    return added, removed

def update_changelog(target_dict: dict, old_text: str, new_text: str, reset_link: bool = False):
    added, removed = calculate_diff(old_text, new_text)
    if "changelog" not in target_dict or not isinstance(target_dict["changelog"], list) or len(target_dict["changelog"]) == 0:
        target_dict["changelog"] = ["None", f"+{added}", f"-{removed}"]
    else:
        cl = target_dict["changelog"]
        while len(cl) < 3:
            cl.append("")
        if reset_link:
            cl[0] = "None"
        cl[1] = f"+{added}"
        cl[2] = f"-{removed}"

def update_top_level_metadata(plugin_obj: dict, source_dict: dict):
    for key in ALWAYS_UPDATE_KEYS:
        if key in source_dict:
            plugin_obj[key] = source_dict[key]

    for key in PURGEABLE_META_KEYS:
        if key in source_dict:
            plugin_obj[key] = source_dict[key]
        elif key in plugin_obj:
            del plugin_obj[key]

def main():
    if len(sys.argv) < 2:
        print("ERROR: Plugin file arguments missing.")
        sys.exit(1)

    file_paths = sys.argv[1:]

    json_path = os.path.join("packit", "plugins.json")
    plugins_data = {"plugins": []}

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                plugins_data = json.load(f)
                for p in plugins_data.get("plugins", []):
                    v = p.get("version")
                    if v and "versions" in p and v in p["versions"]:
                        del p["versions"][v]
        except Exception as e:
            print(f"WARN: Failed to read {json_path}: {e}. Creating new structure.")

    plugins_list = plugins_data.get("plugins", [])

    added_ids = []
    updated_ids = []
    deleted_ids = []

    for file_path in file_paths:
        print(f"INFO: Processing file: {file_path}")

        if not os.path.exists(file_path):
            binary_data = get_deleted_file_content(file_path)
            del_dict = parse_plugin_content(binary_data, file_path) if binary_data else None

            target_plugin = None
            target_index = -1
            del_ver = None
            del_id = None

            if del_dict:
                del_id = del_dict.get("id")
                del_ver = del_dict.get("version")
                for i, plugin in enumerate(plugins_list):
                    if plugin.get("id") == del_id:
                        target_plugin = plugin
                        target_index = i
                        break

            if not target_plugin:
                filename = os.path.basename(file_path)
                for i, plugin in enumerate(plugins_list):
                    if os.path.basename(plugin.get("link", "")) == filename:
                        target_plugin = plugin
                        target_index = i
                        del_id = plugin.get("id")
                        del_ver = plugin.get("version")
                        break
                    versions = plugin.get("versions", {})
                    if isinstance(versions, dict):
                        for v, v_data in versions.items():
                            if isinstance(v_data, dict) and os.path.basename(v_data.get("link", "")) == filename:
                                target_plugin = plugin
                                target_index = i
                                del_id = plugin.get("id")
                                del_ver = v
                                break
                        if target_plugin:
                            break

            if not target_plugin:
                print(f"WARN: File {file_path} deleted, but not found in plugins.json")
                continue

            top_ver = target_plugin.get("version")
            versions = target_plugin.get("versions", {})

            if del_ver == top_ver:
                if not versions:
                    plugins_list.pop(target_index)
                    if del_id in added_ids:
                        added_ids.remove(del_id)
                    if del_id in updated_ids:
                        updated_ids.remove(del_id)
                    if del_id not in deleted_ids:
                        deleted_ids.append(del_id)
                else:
                    prev_ver = list(versions.keys())[-1]
                    prev_entry = versions.pop(prev_ver)
                    
                    prev_link = prev_entry.get("link", "")
                    b = fetch_bytes_for_link(prev_link)
                    if b:
                        prev_temp = parse_plugin_content(b, os.path.join("plugins", os.path.basename(prev_link)))
                        if prev_temp:
                            update_top_level_metadata(target_plugin, prev_temp)

                    target_plugin["version"] = prev_ver
                    target_plugin["link"] = prev_link
                    target_plugin["size"] = prev_entry.get("size", "")
                    
                    if "app_version" in prev_entry:
                        target_plugin["app_version"] = prev_entry["app_version"]
                    elif "app_version" in target_plugin:
                        del target_plugin["app_version"]

                    if "changelog" in prev_entry:
                        target_plugin["changelog"] = prev_entry["changelog"]
                    elif "changelog" in target_plugin:
                        del target_plugin["changelog"]

                    if del_id not in updated_ids and del_id not in deleted_ids:
                        updated_ids.append(del_id)

            elif isinstance(versions, dict) and del_ver in versions:
                all_vers = list(versions.keys()) + [top_ver]
                idx = all_vers.index(del_ver)
                
                has_prev = idx > 0
                has_next = idx < len(all_vers) - 1

                if has_next:
                    next_ver = all_vers[idx+1]
                    next_entry = target_plugin if next_ver == top_ver else versions[next_ver]

                    if not has_prev:
                        next_entry.pop("changelog", None)
                    else:
                        prev_ver = all_vers[idx-1]
                        prev_entry = versions[prev_ver]

                        prev_text = get_plugin_text(prev_entry.get("link"))
                        next_text = get_plugin_text(next_entry.get("link"))
                        update_changelog(next_entry, prev_text, next_text, reset_link=False)
                
                del versions[del_ver]
                
                if del_id not in updated_ids and del_id not in deleted_ids:
                    updated_ids.append(del_id)

        else:
            temp_dict = parse_plugin_file(file_path)
            if not temp_dict:
                continue

            new_text = temp_dict.pop("_raw_text", "")
            plugin_id = temp_dict["id"]
            curr_ver = temp_dict.get("version")

            exists = False
            index = -1
            for i, plugin in enumerate(plugins_list):
                if plugin.get("id") == plugin_id:
                    exists = True
                    index = i
                    break

            if not exists:
                has_dex = temp_dict.pop("has_dex", False)
                temp_dict["release_date"] = temp_dict["update_date"]
                temp_dict["versions"] = {}

                temp_dict["sources"] = {
                    "clients": [
                        "exteraGram",
                        "AyuGram"
                    ],
                    "langs": ["Python", "Java"] if has_dex else ["Python"]
                }

                author = temp_dict.get("author")
                if author in know_authors:
                    temp_dict["team"] = [
                        [
                            know_authors[author],
                            "Developer"
                        ]
                    ]
                plugins_list.append(temp_dict)
                if plugin_id not in added_ids:
                    added_ids.append(plugin_id)
            else:
                temp_dict.pop("has_dex", None)
                main_plugin = plugins_list[index]
                old_top_ver = main_plugin.get("version")
                
                if "versions" not in main_plugin or not isinstance(main_plugin["versions"], dict):
                    main_plugin["versions"] = {}

                if curr_ver == old_top_ver:
                    update_top_level_metadata(main_plugin, temp_dict)
                    if main_plugin["versions"]:
                        prev_ver = list(main_plugin["versions"].keys())[-1]
                        prev_entry = main_plugin["versions"][prev_ver]
                        old_text = get_plugin_text(prev_entry.get("link"))
                        update_changelog(main_plugin, old_text, new_text, reset_link=False)

                elif curr_ver in main_plugin["versions"]:
                    curr_entry = main_plugin["versions"][curr_ver]
                    curr_entry["link"] = temp_dict["link"]
                    curr_entry["size"] = temp_dict["size"]
                    if "app_version" in temp_dict:
                        curr_entry["app_version"] = temp_dict["app_version"]
                    else:
                        curr_entry.pop("app_version", None)

                    all_vers = list(main_plugin["versions"].keys()) + [old_top_ver]
                    idx = all_vers.index(curr_ver)

                    if idx > 0:
                        prev_ver = all_vers[idx-1]
                        prev_entry = main_plugin["versions"][prev_ver]
                        old_text = get_plugin_text(prev_entry.get("link"))
                        update_changelog(curr_entry, old_text, new_text, reset_link=False)
                    else:
                        curr_entry.pop("changelog", None)

                    if idx < len(all_vers) - 1:
                        next_ver = all_vers[idx+1]
                        next_entry = main_plugin if next_ver == old_top_ver else main_plugin["versions"][next_ver]
                        next_text = get_plugin_text(next_entry.get("link"))
                        update_changelog(next_entry, new_text, next_text, reset_link=False)

                else:
                    ver_entry = {
                        "link": main_plugin.get("link", ""),
                        "size": main_plugin.get("size", "")
                    }
                    if "app_version" in main_plugin:
                        ver_entry["app_version"] = main_plugin["app_version"]
                    if "changelog" in main_plugin:
                        ver_entry["changelog"] = main_plugin["changelog"]

                    main_plugin["versions"][old_top_ver] = ver_entry

                    update_top_level_metadata(main_plugin, temp_dict)

                    old_text = get_plugin_text(ver_entry["link"])
                    update_changelog(main_plugin, old_text, new_text, reset_link=True)

                if plugin_id not in updated_ids and plugin_id not in added_ids:
                    updated_ids.append(plugin_id)

    plugins_data["plugins"] = plugins_list

    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(plugins_data, f, ensure_ascii=False, indent=2)

    print(f"INFO: Successfully saved {json_path}")

    title_parts = []
    body_parts = []

    if added_ids:
        if len(added_ids) == 1:
            title_parts.append(f"Added {added_ids[0]} plugin")
        else:
            title_parts.append(f"Added {len(added_ids)} plugins")
            body_parts.append(f"Added: {', '.join(added_ids)}")

    if updated_ids:
        if len(updated_ids) == 1:
            title_parts.append(f"Updated {updated_ids[0]} plugin")
        else:
            title_parts.append(f"Updated {len(updated_ids)} plugins")
            body_parts.append(f"Updated: {', '.join(updated_ids)}")

    if deleted_ids:
        if len(deleted_ids) == 1:
            title_parts.append(f"Deleted {deleted_ids[0]} plugin")
        else:
            title_parts.append(f"Deleted {len(deleted_ids)} plugins")
            body_parts.append(f"Deleted: {', '.join(deleted_ids)}")

    if title_parts:
        commit_title = ", ".join(title_parts) + f" in {json_path}"
        commit_body = "\n".join(body_parts)

        with open("/tmp/commit_msg.txt", "w", encoding="utf-8") as f:
            f.write(commit_title)
            if commit_body:
                f.write("\n\n" + commit_body)

if __name__ == "__main__":
    main()