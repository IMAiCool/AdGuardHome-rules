import os
import re

# 输入文件
input_file = './temp/Merge-rule/merge_rules.txt'

# 输出目录
output_dir = './temp/Classification'
os.makedirs(output_dir, exist_ok=True)

hosts_path = os.path.join(output_dir, 'hosts')
adguard_rules_path = os.path.join(output_dir, 'adguard-rules.txt')
domain_path = os.path.join(output_dir, 'domain.txt')
others_path = os.path.join(output_dir, 'others.txt')

# IPv4 匹配（简化）
ipv4_pattern = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}'

# IPv6 匹配（简化，包含 :: 和常见格式）
ipv6_pattern = (
    r'(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,7}:|'
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|'
    r'([0-9a-fA-F]{1,4}:){1,4}:'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))'
)

def is_ip(s):
    s = s.strip()
    if s == '::':  # IPv6 shorthand for unspecified address
        return True
    if re.fullmatch(ipv4_pattern, s):
        return True
    if re.fullmatch(ipv6_pattern, s):
        return True
    return False

def is_hosts_rule(line):
    parts = line.split()
    if len(parts) != 2:
        return False
    ip, domain = parts
    return is_ip(ip)

def is_adguard_rule(line):
    line = line.strip()
    if line.startswith('@@'):
        line = line[2:]
    if not line.startswith('||'):
        return False
    # 允许 || 后面是字母数字 . - *，结尾允许 ^ 后面跟多个 * 或 $important 或 | 或无
    pattern = r'^\|\|[\w\.\-\*]+(\^(?:\*+|\$important|\|)?)?$'
    return bool(re.match(pattern, line))

def is_domain_rule(line):
    # 允许以点开头或不以点开头，后面跟域名，末尾可带^
    pattern = r'^\.?[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+\^?$'
    return bool(re.match(pattern, line.strip()))

# 读取规则
with open(input_file, 'r', encoding='utf-8') as f:
    lines = [line.strip() for line in f if line.strip()]

hosts_list = []
adguard_list = []
domain_list = []
others_list = []

for line in lines:
    if is_hosts_rule(line):
        hosts_list.append(line)
    elif is_adguard_rule(line):
        adguard_list.append(line)
    elif is_domain_rule(line):
        domain_list.append(line)
    else:
        others_list.append(line)

def write_lines(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

write_lines(hosts_path, hosts_list)
write_lines(adguard_rules_path, adguard_list)
write_lines(domain_path, domain_list)
write_lines(others_path, others_list)

print(f"分类完成:")
print(f" - hosts: {len(hosts_list)} 条")
print(f" - adguard-rules.txt: {len(adguard_list)} 条")
print(f" - domain.txt: {len(domain_list)} 条")
print(f" - others.txt: {len(others_list)} 条")
