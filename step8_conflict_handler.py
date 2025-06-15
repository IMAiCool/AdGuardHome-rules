import os

def load_lines_with_index(path):
    lines = []
    index_map = {}
    if not os.path.exists(path):
        print(f"文件不存在: {path}")
        return lines, index_map
    with open(path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if line:
                lines.append(line)
                index_map[line] = idx
    return lines, index_map

def get_parent_domains(domain):
    parts = domain.split('.')
    return ['.'.join(parts[i:]) for i in range(1, len(parts))]

# 创建所需目录
os.makedirs('./temp/TMP', exist_ok=True)
os.makedirs('./temp/Log', exist_ok=True)
os.makedirs('./output', exist_ok=True)

# 读取黑白名单
blacklist, black_index = load_lines_with_index('./temp/ipombaw/BlackList_tmp.txt')
whitelist, white_index = load_lines_with_index('./temp/ipombaw/WhiteList_tmp.txt')

both_log = []
new_blacklist = []
new_whitelist = []

black_set = set(blacklist)
white_set = set(whitelist)

# 冲突检测处理
for w in whitelist:
    if w in black_set:
        parents = get_parent_domains(w)
        found_parent = None
        for p in parents:
            if p in black_set:
                found_parent = p
                break
        if found_parent:
            both_log.append(
                f"{w} 存在于黑白名单\nWhiteLine#{white_index[w]} BlackLine#{black_index[w]} 父域: {found_parent}@BlackLine#{black_index[found_parent]}"
            )
            new_whitelist.append(w)
        else:
            both_log.append(
                f"{w} 存在于黑白名单\nWhiteLine#{white_index[w]} BlackLine#{black_index[w]}"
            )
    else:
        new_whitelist.append(w)

# 黑名单排除冲突项
new_blacklist = [b for b in blacklist if b not in white_set]

# 写入临时文件
with open('./temp/TMP/White_list_tmp.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_whitelist))
with open('./temp/TMP/Black_list_tmp.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_blacklist))
with open('./temp/Log/both-in-white-and-black.log', 'w', encoding='utf-8') as f:
    f.write('\n\n'.join(both_log))

# ============ 层级冲突检测 ============
def detect_hierarchy_conflict(lines, source_file, output_file, log_path):
    seen = {}
    conflict_log = []
    final_list = []

    for idx, line in enumerate(lines, 1):
        conflict_found = False
        parts = line.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in seen:
                conflict_log.append(
                    f"{line}#{source_file}第{idx}行 与上级域名{parent}#{source_file}第{seen[parent]}行 存在层级冲突"
                )
                conflict_found = True
                break
        if not conflict_found:
            seen[line] = idx
            final_list.append(line)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_list))

    # 附加写入冲突日志
    if conflict_log:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write('\n'.join(conflict_log) + '\n')

# 执行黑白名单层级冲突检测
detect_hierarchy_conflict(
    new_blacklist,
    'Black_list_tmp.txt',
    './temp/TMP/AdBlackList.txt',
    './temp/Log/Hierarchy_conflict.log'
)

detect_hierarchy_conflict(
    new_whitelist,
    'White_list_tmp.txt',
    './temp/TMP/AdWhiteList.txt',
    './temp/Log/Hierarchy_conflict.log'
)
