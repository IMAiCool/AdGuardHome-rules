import os

# 输入文件列表
blacklist_files = [
    './temp/stripping_rules/hosts-bdomain.txt',
    './temp/stripping_rules/adguard-bdomain.txt',
    './temp/stripping_rules/domain.txt',
]

whitelist_files = [
    './temp/stripping_rules/adguard-wdomain.txt',
    './temp/stripping_rules/hosts-odomain.txt',
]

# 输出目录与文件路径
output_dir = './temp/ipombaw'
os.makedirs(output_dir, exist_ok=True)
blacklist_output = os.path.join(output_dir, 'BlackList_tmp.txt')
whitelist_output = os.path.join(output_dir, 'WhiteList_tmp.txt')

def merge_and_dedup(file_list):
    result_set = set()
    for file_path in file_list:
        if not os.path.exists(file_path):
            print(f"警告：找不到文件 {file_path}")
            continue
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    result_set.add(line)
    return sorted(result_set)

# 合并并写出结果
def write_result(output_path, lines):
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"已写入：{output_path}（{len(lines)} 条）")

# 黑白名单处理
blacklist = merge_and_dedup(blacklist_files)
whitelist = merge_and_dedup(whitelist_files)

write_result(blacklist_output, blacklist)
write_result(whitelist_output, whitelist)
