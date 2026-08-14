# AdGuard Home 规则合并工具

从多个远程规则源和本地规则中提取 AdGuard Home 可用的域名规则，完成合并、分类、冲突处理、层级精简及格式标准化。

## 输入

- `input/urls.conf`：远程规则源，每行格式为 `名称: URL`；空行以及以 `#`、`!` 开头的行会被忽略。
- `input/local-rules.txt`：本地补充规则。

支持纯域名（`example.com`）、hosts（`0.0.0.0 example.com`）和 AdGuard 域名锚点（`||example.com^`、`@@||example.com^$important`）。URL、正则、元素隐藏规则等非域名规则不会进入输出。

## 输出

所有产物统一位于 `output/`，固定为以下 4 个文件，不再生成 `temp/` 中间目录：

- `BlackList_Raw.txt`：未清洗黑名单。保留来源格式，仅移除注释/空行并按原始行精确去重，再按纯域名、hosts、AdGuard 格式和域名排序。
- `WhiteList_Raw.txt`：未清洗白名单。规则处理和排序方式同上。
- `BlackList.txt`：清洗、冲突处理、域名层级精简及去重后的黑名单，格式为 `||example.com^`。
- `WhiteList.txt`：清洗、冲突处理、域名层级精简及去重后的白名单，格式为 `@@||example.com^$important`。

同一域名同时出现时白名单优先。同一名单中已有父域名时删除普通子域名；通配符域名单独保留，避免改变语义。

## 运行

Python 3.10 及以上版本无需第三方依赖：

```bash
python script.py
```

仅处理本地规则并跳过下载：

```bash
python script.py --no-download
```

单个远程源失败不会中断其他来源。输出采用原子替换，避免执行中断留下不完整文件。

## 自动更新与直达链接

GitHub Actions 每 8 小时运行一次并提交 `output/`。jsDelivr 加速链接：

- [未清洗黑名单](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList_Raw.txt)
- [未清洗白名单](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList_Raw.txt)
- [清洗黑名单](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList.txt)
- [清洗白名单](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList.txt)

所有处理均已整合到唯一脚本 `script.py`：读取 → 精确合并去重 → 格式识别及分类 → 输出未清洗黑白名单 → 标准化 → 冲突与层级精简 → 输出清洗黑白名单。
