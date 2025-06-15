import os
import glob
import re

# 路径配置
input_local_rules_file = './input/local-rules.txt'
downloaded_rules_pattern = './temp/local/*.txt'
output_dir = './temp/Merge-rule'
os.makedirs(output_dir, exist_ok=True)

merge_rules_path = os.path.join(output_dir, 'merge_rules.txt')
merge_others_path = os.path.join(output_dir, 'merge_others.txt')

# 收集规则
rules = set()

# 加载本地规则文件
if os.path.exists(input_local_rules_file):
    with open(input_local_rules_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                rules.add(line)

# 加载下载的规则文件
for filepath in glob.glob(downloaded_rules_pattern):
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                rules.add(line)

# 排序后的唯一规则列表
rules = sorted(rules)

# 正则与配置
special_chars_pattern = r'[![\]/\\?=+\(#\)&%]'
invalid_endings = ['^', '^|', '^$important','*']

# 分类结果
merge_rules = []
merge_others = []

for line in rules:
    # ① 特殊字符检查
    if re.search(special_chars_pattern, line):
        merge_others.append(line)
        continue

    # ② 包含 'local' 或 'host' 或 '.js'
    if 'local' in line or 'host' in line:
        merge_others.append(line)
        continue

    # ③ 判断特殊结尾
    if any(line.endswith(suffix) for suffix in invalid_endings):
        merge_rules.append(line)
        continue

    # ④ 非字母结尾
    if not line or not line[-1].isalpha():
        merge_others.append(line)
        continue

    # ⑤ 最后一个字母前是否有 ^
    last_letter_index = None
    for i in range(len(line)-1, -1, -1):
        if line[i].isalpha():
            last_letter_index = i
            break

    if last_letter_index is not None and '^' in line[:last_letter_index]:
        merge_others.append(line)
        continue

    # 通过所有判断
    merge_rules.append(line)

# 写入输出文件
with open(merge_rules_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(merge_rules))

with open(merge_others_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(merge_others))

# print(f"✅ 处理完成：")
print(f" - merge_rules.txt：{len(merge_rules)} 条")
print(f" - merge_others.txt：{len(merge_others)} 条")
