import os

# 输入路径
hosts_input = './temp/Classification/hosts'
adguard_input = './temp/Classification/adguard-rules.txt'

# 输出路径
output_dir = './temp/BAWLC'
os.makedirs(output_dir, exist_ok=True)

hosts_black_path = os.path.join(output_dir, 'hosts_black.txt')
hosts_others_path = os.path.join(output_dir, 'hosts_others.txt')
adguard_black_path = os.path.join(output_dir, 'adguard-black.txt')
adguard_white_path = os.path.join(output_dir, 'adguard-white.txt')

# 合法黑名单IP集合
blacklist_ips = {'0.0.0.0', '127.0.0.1', '::'}

# 分类 hosts 文件
hosts_black = []
hosts_others = []

if os.path.exists(hosts_input):
    with open(hosts_input, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                continue
            ip, domain = parts
            if ip in blacklist_ips:
                hosts_black.append(line)
            else:
                hosts_others.append(line)

# 分类 adguard 规则
adguard_black = []
adguard_white = []

if os.path.exists(adguard_input):
    with open(adguard_input, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('@@'):
                adguard_white.append(line)
            elif line.startswith('||'):
                adguard_black.append(line)

# 写入文件
def write_list(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

write_list(hosts_black_path, hosts_black)
write_list(hosts_others_path, hosts_others)
write_list(adguard_black_path, adguard_black)
write_list(adguard_white_path, adguard_white)

print("黑白名单分类完成：")
print(f" - hosts_black.txt：{len(hosts_black)} 条")
print(f" - hosts_others.txt：{len(hosts_others)} 条")
print(f" - adguard-black.txt：{len(adguard_black)} 条")
print(f" - adguard-white.txt：{len(adguard_white)} 条")
