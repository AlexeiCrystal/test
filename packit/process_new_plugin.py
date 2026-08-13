import os
import sys
import re
import json
import struct
import hashlib
from datetime import datetime

P0 = 0x9E3779B97F4A7C15
P1 = 0x6C62272E07BB0142
P2 = 0x94D049BB133111EB
P3 = 0xBF58476D1CE4E5B9
MASK64 = 0xFFFFFFFFFFFFFFFF

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

def main():
    if len(sys.argv) < 2:
        print("ERROR: Plugin file path argument missing.")
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"INFO: Processing file: {file_path}")

    if not os.path.exists(file_path):
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)

    with open(file_path, "rb") as f:
        binary_data = f.read()

    try:
        text_content = binary_data.decode("utf-8")
    except UnicodeDecodeError:
        text_content = binary_data.decode("latin-1")

    temp_dict = {}

    id_match = re.search(r'__id__\s*=\s*["\']([^"\']+)["\']', text_content)
    if not id_match:
        print(f"ERROR: __id__ not found in {file_path}")
        sys.exit(1)
    
    plugin_id = id_match.group(1)
    temp_dict["id"] = plugin_id
    print(f'INFO: Extracted plugin id "{plugin_id}"')

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
            print(f'INFO: Extracted {key}: "{match.group(1)}"')

    desc_match = re.search(r'__description__\s*=\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|["\']([^"\']+)["\'])', text_content, re.DOTALL)
    if desc_match:
        desc_val = next(g for g in desc_match.groups() if g is not None)
        temp_dict["description"] = desc_val
        print("INFO: Extracted description")
    else:
        print("WARN: Plugin description not found")

    min_ver_match = re.search(r'__min_version__\s*=\s*["\']([^"\']+)["\']', text_content)
    app_ver_match = re.search(r'__app_version__\s*=\s*["\']([^"\']+)["\']', text_content)

    if app_ver_match:
        temp_dict["app_version"] = app_ver_match.group(1)
        print(f'INFO: Extracted app_version: "{app_ver_match.group(1)}"')
    elif min_ver_match:
        temp_dict["app_version"] = f">={min_ver_match.group(1)}"
        print(f'INFO: Extracted app_version from min_version: ">={min_ver_match.group(1)}"')

    sha256_hash = hashlib.sha256(binary_data).hexdigest()
    temp_dict["hash"] = sha256_hash
    print(f"INFO: Calculated SHA256: {sha256_hash}")

    bithash_val = calculate_bithash(binary_data)
    temp_dict["bithash"] = bithash_val
    print(f"INFO: Calculated BitHash: {bithash_val}")

    file_size_str = format_size(len(binary_data))
    temp_dict["size"] = file_size_str
    print(f"INFO: Calculated size: {file_size_str}")

    filename = os.path.basename(file_path)
    temp_dict["link"] = f"https://github.com/AlexeiCrystal/extera-plugins/raw/main/plugins/{filename}"

    check_str = f"{filename} {temp_dict.get('version', '')}".lower()
    if "beta" in check_str or "бета" in check_str:
        temp_dict["state"] = "beta"
    elif "alpha" in check_str or "альфа" in check_str:
        temp_dict["state"] = "alpha"
    else:
        temp_dict["state"] = "release"
    print(f'INFO: Set state: {temp_dict["state"]}')

    current_date = datetime.now().strftime("%d.%m.%Y")
    temp_dict["update_date"] = current_date

    temp_dict["sources"] = {
        "clients": [
            "exteraGram",
            "AyuGram"
        ]
    }

    if temp_dict.get("author") == "@AlexeiCrystal":
        temp_dict["team"] = [
            [
                "1169951070",
                "Developer"
            ]
        ]

    json_path = os.path.join("packit", "plugins.json")
    plugins_data = {"plugins": []}

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                plugins_data = json.load(f)
        except Exception as e:
            print(f"WARN: Failed to read {json_path}: {e}. Creating new structure.")

    plugins_list = plugins_data.get("plugins", [])
    
    exists = False
    index = -1
    for i, plugin in enumerate(plugins_list):
        if plugin.get("id") == plugin_id:
            exists = True
            index = i
            break

    if exists:
        print(f'INFO: Plugin "{plugin_id}" found in main dictionary. Updating...')
        main_plugin = plugins_list[index]
        
        temp_dict["release_date"] = main_plugin.get("release_date", temp_dict["update_date"])

        if "versions" in main_plugin and isinstance(main_plugin["versions"], dict):
            temp_dict["versions"] = main_plugin["versions"].copy()
        else:
            temp_dict["versions"] = {}

        old_ver = main_plugin.get("version")
        if old_ver and old_ver not in temp_dict["versions"]:
            ver_entry = {}
            for k in ["app_version", "changelog", "link", "size"]:
                if k in main_plugin:
                    ver_entry[k] = main_plugin[k]
            temp_dict["versions"][old_ver] = ver_entry

        curr_ver = temp_dict.get("version")
        if curr_ver:
            curr_entry = {}
            if "app_version" in temp_dict:
                curr_entry["app_version"] = temp_dict["app_version"]
            curr_entry["link"] = temp_dict["link"]
            curr_entry["size"] = temp_dict["size"]
            
            temp_dict["versions"][curr_ver] = curr_entry

        for k, v in main_plugin.items():
            if k not in temp_dict:
                temp_dict[k] = v

        plugins_list[index] = temp_dict
        commit_msg = f'Update plugin "{plugin_id}" in packit/plugins.json'
    else:
        print(f'INFO: Plugin "{plugin_id}" not found in main dictionary. Adding...')
        temp_dict["release_date"] = temp_dict["update_date"]
        temp_dict["versions"] = {}

        curr_ver = temp_dict.get("version")
        if curr_ver:
            curr_entry = {}
            if "app_version" in temp_dict:
                curr_entry["app_version"] = temp_dict["app_version"]
            curr_entry["link"] = temp_dict["link"]
            curr_entry["size"] = temp_dict["size"]
            
            temp_dict["versions"][curr_ver] = curr_entry

        plugins_list.append(temp_dict)
        commit_msg = f'Add plugin "{plugin_id}" to packit/plugins.json'

    plugins_data["plugins"] = plugins_list

    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(plugins_data, f, ensure_ascii=False, indent=2)

    print(f"INFO: Successfully saved {json_path}")

    github_output = os.getenv('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a', encoding='utf-8') as f:
            f.write(f"commit_message={commit_msg}\n")
            f.write(f"plugin_id={plugin_id}\n")

if __name__ == "__main__":
    main()
