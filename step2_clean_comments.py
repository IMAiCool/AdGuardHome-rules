import glob
import os
import shutil
import re

def remove_comments_and_blank_lines(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    with open(filename, 'w', encoding='utf-8') as f:
        for line in lines:
            # 删除行中以空白或行首出现的 # 或 ! 及其后的内容
            match = re.search(r'(^|\s)([#!])', line)
            if match:
                line = line[:match.start()].rstrip()
            else:
                line = line.rstrip()

            # 跳过空行
            if line.strip() == '':
                continue

            f.write(line + '\n')

def process_all_txt_files(input_dir='./temp/local', backup_dir='./temp/backup_local'):
    os.makedirs(backup_dir, exist_ok=True)
    txt_files = glob.glob(os.path.join(input_dir, '*.txt'))

    for file_path in txt_files:
        filename = os.path.basename(file_path)
        backup_path = os.path.join(backup_dir, filename)

        print(f'备份 {file_path} 到 {backup_path}')
        shutil.copy2(file_path, backup_path)

        print(f'处理 {file_path}（删除注释和空行）')
        remove_comments_and_blank_lines(file_path)
# 执行
process_all_txt_files()
