import subprocess
import sys

def run_script(script_name):
    """执行指定Python脚本"""
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            check=True,
            text=True,
            capture_output=True
        )
        print(f"✅ {script_name} 执行成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {script_name} 执行失败:")
        print(e.stderr)
        return False

if __name__ == "__main__":
    # 执行顺序列表
    scripts = [
        "step1_download_rules.py",        # 下载规则
        "step2_clean_comments.py",        #去除注释
        "step3_merge_rules.py",           # 合并规则
        "step4_classify_rules.py",        # 分类规则
        "step5_classify_black_white.py",  # 黑白名单分类
        "step6_strip_domains.py",         # 域名提取
        "step7_combine_black_white.py",   # 合并黑白名单
        "step8_conflict_handler.py",      # 冲突处理
        "step9_rule_standardizer.py"      # 规则标准化
    ]

    print("🚀 开始执行过滤规则处理流程...")
    for script in scripts:
        if not run_script(script):
            print(f"中断执行，请先解决 {script} 的问题")
            sys.exit(1)
    # 删除.js^拦截
    with open('./temp/TMP/AdGuardHomeBlack.txt', 'r',encoding='utf-8') as file:
        lines = file.readlines()
    filtered_lines = [line for line in lines if not line.endswith('.js^\n')]
    with open('./output/BlackList.txt', 'w',encoding='utf-8') as file:
        file.writelines(filtered_lines)
    # 删除.js^拦截
    with open('./temp/TMP/AdGuardHomeWhite.txt', 'r',encoding='utf-8') as file:
        lines = file.readlines()
    filtered_lines = [line for line in lines if not line.endswith('.js^\n')]
    with open('./output/WhiteList.txt', 'w',encoding='utf-8') as file:
        file.writelines(filtered_lines)

    print("🎉 所有处理步骤已完成！")