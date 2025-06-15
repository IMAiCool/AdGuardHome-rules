import os
import requests

# 路径定义
input_path = './input/urls.conf'
output_dir = './temp/local'

# 确保输出目录存在
os.makedirs(output_dir, exist_ok=True)

# 读取规则列表
with open(input_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for line in lines:
    line = line.strip()
    if not line or ':' not in line:
        continue  # 忽略空行或格式错误的行

    rule_name, url = map(str.strip, line.split(':', 1))
    try:
        print(f"正在下载 {rule_name} 从 {url}...")
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        output_file = os.path.join(output_dir, f"{rule_name}.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(response.text)

        print(f"已保存到 {output_file}\n")

    except requests.RequestException as e:
        print(f"❌ 下载失败: {rule_name} ({url})\n错误信息: {e}\n")
