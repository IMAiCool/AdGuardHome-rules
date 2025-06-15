import os
import re

# 输出目录
output_dir = './temp/stripping_rules'
os.makedirs(output_dir, exist_ok=True)

# 路径定义
paths = {
    'hosts_black': ('./temp/BAWLC/hosts_black.txt', 'hosts-bdomain.txt'),
    'hosts_others': ('./temp/BAWLC/hosts_others.txt', 'hosts-odomain.txt'),
    'adguard_black': ('./temp/BAWLC/adguard-black.txt', 'adguard-bdomain.txt'),
    'adguard_white': ('./temp/BAWLC/adguard-white.txt', 'adguard-wdomain.txt'),
    'domain': ('./temp/Classification/domain.txt', 'domain.txt'),
}

# 剥离逻辑函数
def strip_hosts_line(line):
    parts = line.strip().split()
    if len(parts) == 2:
        domain = parts[1].strip().rstrip('^')
        return domain
    return None

def strip_adguard_line(line):
    line = line.strip()
    line = re.sub(r'^@@', '', line)
    line = re.sub(r'^\|\|', '', line)
    domain = re.sub(r'\^.*$', '', line)  # 去除 ^ 及其后内容
    return domain.strip()

def strip_domain_line(line):
    return line.strip().rstrip('^')

# 处理函数
def process_file(input_path, output_path, strip_func):
    if not os.path.exists(input_path):
        print(f'文件不存在: {input_path}')
        return
    result = []
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = strip_func(line)
            if stripped:
                result.append(stripped)
    with open(os.path.join(output_dir, output_path), 'w', encoding='utf-8') as f:
        f.write('\n'.join(result))
    print(f"已生成: {output_path}（{len(result)} 条）")

# 执行剥离
process_file(*paths['hosts_black'], strip_hosts_line)
process_file(*paths['hosts_others'], strip_hosts_line)
process_file(*paths['adguard_black'], strip_adguard_line)
process_file(*paths['adguard_white'], strip_adguard_line)
process_file(*paths['domain'], strip_domain_line)
