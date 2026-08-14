# AdGuard Home 规则合并工具

用于聚合远程规则源和本地补充规则，生成黑名单与白名单。清洗后的标准化规则适用于 AdGuard Home；保留来源格式的未清洗规则可用于 AdGuard，也方便检查和调试原始规则。

项目已将下载、解析、分类、去重、冲突处理、层级精简和格式化整合到单个 Python 脚本中。运行过程不再创建多级临时目录，所有规则产物统一写入 `output/`。

## 功能特性

- 同时读取远程订阅和本地补充规则。
- 支持纯域名、hosts 和 AdGuard 域名锚点规则。
- 按黑名单、白名单及来源格式稳定排序。
- 对来源规则进行精确去重，对最终域名进行标准化去重。
- 白名单优先处理同域名黑白冲突。
- 删除已被父域名覆盖的普通子域名，减少最终规则体积。
- 保留通配符域名，避免层级精简改变其匹配语义。
- 单个远程源下载失败不会中断整个任务。
- 使用原子替换写入文件，避免中途退出产生不完整结果。
- 仅使用 Python 标准库，无需安装第三方依赖。

## 项目结构

```text
AdGuardHome-rules/
├─ .github/
│  └─ workflows/
│     └─ scheduled-run.yml    # 每 8 小时自动生成和提交规则
├─ input/
│  ├─ urls.conf               # 远程规则源配置
│  └─ local-rules.txt         # 本地补充规则
├─ output/
│  ├─ BlackList_Raw.txt       # 未清洗黑名单
│  ├─ WhiteList_Raw.txt       # 未清洗白名单
│  ├─ BlackList.txt           # 清洗后的黑名单
│  └─ WhiteList.txt           # 清洗后的白名单
├─ .gitignore
├─ README.md
└─ script.py                  # 唯一处理脚本
```

## 输入配置

### 远程规则源

在 `input/urls.conf` 中按以下格式配置，每行一个来源：

```text
规则名称: https://example.com/rules.txt
```

空行以及以 `#` 或 `!` 开头的行会被忽略。名称与 URL 使用第一个冒号分隔，因此 URL 中的 `https://` 不受影响。

### 本地规则

将自定义规则写入 `input/local-rules.txt`。支持的输入形式如下：

```text
# 纯域名，归入黑名单
example.com

# hosts 黑名单
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
:: telemetry.example.com

# 非拦截 IP 的 hosts 规则，归入白名单
192.0.2.1 allowed.example.com

# AdGuard 黑白名单
||ads.example.com^
@@||allowed.example.com^$important
```

输入读取时会忽略空行、规则头部以及以 `!`、`#`、`[` 开头的整行注释。行尾由空白分隔的 `!` 或 `#` 注释也会被移除。

以下内容不会进入输出：

- 无法解析为合法域名的条目；
- `localhost`、`localhost.localdomain` 和纯 IP；
- URL 路径规则、正则规则、元素隐藏规则等非域名规则；
- 不属于纯域名、双字段 hosts 或 AdGuard `||` 域名锚点格式的内容。

## 处理流程

```text
读取本地规则和远程来源
        ↓
移除注释、空行并按原始规则精确去重
        ↓
识别纯域名 / hosts / AdGuard 格式
        ↓
区分黑名单与白名单并输出 Raw 文件
        ↓
域名小写化、尾点处理及有效性校验
        ↓
白名单优先解决同域名冲突
        ↓
精简被父域名覆盖的普通子域名
        ↓
转换为统一 AdGuard 格式并输出最终文件
```

同一个域名同时出现在黑名单和白名单时，将从最终黑名单中移除并保留在白名单中。黑白名单内部若同时存在 `example.com` 和 `sub.example.com`，最终仅保留父域名 `example.com`。以 `*.` 开头的通配符域名不参与普通父子域精简。

## 输出说明

| 文件 | 处理程度 | 输出格式 |
| --- | --- | --- |
| `BlackList_Raw.txt` | 已分类、按原始规则精确去重，未进行最终域名清洗和层级精简 | 保留输入规则格式 |
| `WhiteList_Raw.txt` | 已分类、按原始规则精确去重，未进行最终域名清洗和层级精简 | 保留输入规则格式 |
| `BlackList.txt` | 已标准化、解决冲突、精简层级并去重 | `||example.com^` |
| `WhiteList.txt` | 已标准化、解决冲突、精简层级并去重 | `@@||example.com^$important` |

Raw 文件会先按纯域名、hosts、AdGuard 格式排序，再按域名和原始文本排序。最终文件按标准化域名字典序排列。

- 清洗规则 `BlackList.txt` 和 `WhiteList.txt`：适用于 AdGuard Home。
- 未清洗规则 `BlackList_Raw.txt` 和 `WhiteList_Raw.txt`：保留输入格式，可用于 AdGuard。

## 运行方式

需要 Python 3.10 或更高版本。

下载远程来源并执行完整处理：

```bash
python script.py
```

仅处理 `input/local-rules.txt`，不访问网络：

```bash
python script.py --no-download
```

程序结束时会输出合并规则数以及最终黑白名单数量。远程源单个下载失败时会显示警告，并继续处理其他可用来源。

## 自动更新

`.github/workflows/scheduled-run.yml` 支持以下触发方式：

- 每 8 小时自动运行一次；
- 在 GitHub Actions 页面手动触发。

自动任务使用 Python 3.11 运行 `script.py`，并由 `github-actions[bot]` 提交生成后的规则变化。

## jsDelivr 加速链接

### 未清洗规则

- [BlackList_Raw.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList_Raw.txt)
- [WhiteList_Raw.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList_Raw.txt)

### 清洗规则

- [BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList.txt)
- [WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList.txt)

jsDelivr 存在短暂缓存延迟。仓库更新后若未立即获取到新内容，请稍后重试。

## 注意事项

- 清洗后的规则面向 AdGuard Home 域名级过滤；未清洗规则可用于 AdGuard，但不保证覆盖浏览器扩展支持的全部 Adblock 语法。
- 白名单中使用 `$important`，用于提高例外规则的优先级。
- 上游规则的内容和可用性由各自维护者负责；下载失败的来源应在 `input/urls.conf` 中及时更新。
- 建议先检查未清洗文件定位来源规则，再根据清洗文件中的最终结果排查误拦截。
