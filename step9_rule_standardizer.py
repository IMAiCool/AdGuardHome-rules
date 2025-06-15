import os
from datetime import datetime

def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def ends_with_non_alpha(line):
    # 判断是否以非字母结尾
    return not line[-1].isalpha()

def standardize(lines, is_white):
    prefix = "@@||" if is_white else "||"
    # 添加 ^ 结尾
    return [f"{prefix}{line}^" for line in lines]

def write_file(path, lines, header):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(header + '\n' + '\n'.join(lines))

def main():
    white_input = './temp/TMP/AdWhiteList.txt'
    black_input = './temp/TMP/AdBlackList.txt'
    white_output = './temp/TMP/AdGuardHomeWhite.txt'
    black_output = './temp/TMP/AdGuardHomeBlack.txt'
    log_others = './temp/Log/others.txt'

    os.makedirs('./output', exist_ok=True)
    os.makedirs('./temp/Log', exist_ok=True)

    white_raw = read_lines(white_input)
    black_raw = read_lines(black_input)

    others = []
    white_valid = []
    black_valid = []

    for line in white_raw:
        if ends_with_non_alpha(line):
            others.append(f"[White] {line}")
        else:
            white_valid.append(line)

    for line in black_raw:
        if ends_with_non_alpha(line):
            others.append(f"[Black] {line}")
        else:
            black_valid.append(line)

    with open(log_others, 'w', encoding='utf-8') as f:
        f.write('\n'.join(others))

    now = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')

    white_header = f"""! 规则更新时间 {now}
! 本规则数量 {len(white_valid)}条
! 更新频率 12小时
! 规则名称 白名单规则
"""

    black_header = f"""! 规则更新时间 {now}
! 本规则数量 {len(black_valid)}条
! 更新频率 12小时
! 规则名称 黑名单规则
"""

    white_std = standardize(white_valid, is_white=True)
    black_std = standardize(black_valid, is_white=False)

    write_file(white_output, white_std, white_header)
    write_file(black_output, black_std, black_header)

    print("格式标准化完成，结果输出到 ./output 文件夹，日志输出到 ./temp/Log/others.txt")

if __name__ == '__main__':
    main()
