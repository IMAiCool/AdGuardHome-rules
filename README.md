# AdGuard Home 规则合并工具

用于聚合远程规则源和本地补充规则，生成 AdGuard Home 域名黑白名单，并按 AdGuard、Adblock Plus 和 uBlock Origin 的语法能力分别生成浏览器扩展订阅。

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
- 最终清洗时仅接受 `0.0.0.0`、`127.0.0.0/8` 黑名单和公网 IP hosts 映射。
- 提供 `RuleProcessor` 类接口，便于定时任务及其他 Python 程序调用。
- 仅使用 Python 标准库，无需安装第三方依赖。

## 项目结构

```text
AdGuardHome-rules/
├─ .github/
│  └─ workflows/
│     └─ scheduled-run.yml    # 每 8 小时自动生成和提交规则
├─ input/
│  ├─ urls.json               # 标准 JSON 远程规则源配置
│  └─ local-rules.txt         # 本地补充规则
├─ output/
│  ├─ BlackList_Raw.txt       # 浏览器兼容黑名单（保留有效子域名）
│  ├─ WhiteList_Raw.txt       # 浏览器兼容白名单（保留有效子域名）
│  ├─ BlackList.txt           # 清洗后的黑名单
│  ├─ WhiteList.txt           # 清洗后的白名单
│  ├─ AdGuardHome.txt         # AdGuard Home 合并规则
│  ├─ AdGuard.txt             # AdGuard 浏览器扩展订阅
│  ├─ AdblockPlus.txt         # Adblock Plus 浏览器扩展订阅
│  ├─ uBlockOrigin.txt        # uBlock Origin 浏览器扩展订阅
│  ├─ AdGuard_BlackList.txt / AdGuard_WhiteList.txt
│  ├─ AdblockPlus_BlackList.txt / AdblockPlus_WhiteList.txt
│  └─ uBlockOrigin_BlackList.txt / uBlockOrigin_WhiteList.txt
├─ .gitignore
├─ README.md
└─ script.py                  # 唯一处理脚本
```

## 输入配置

### 远程规则源

远程来源使用标准 JSON 文件 `input/urls.json`：

```json
{
  "sources": [
    {
      "name": "示例规则",
      "url": "https://example.com/rules.txt",
      "enabled": true
    }
  ]
}
```

`sources` 必须是数组，每个来源必须包含非空的 `name` 和 HTTP(S) `url`。`enabled` 为可选布尔值，默认为 `true`；设为 `false` 可临时禁用来源。JSON 不支持注释和尾随逗号，配置不合法时程序会直接报告具体字段错误。

### 本地规则

将自定义规则写入 `input/local-rules.txt`。支持的输入形式如下：

```text
# 纯域名，归入黑名单
example.com

# 0.0.0.0 和 127.0.0.0/8 hosts，归入黑名单
0.0.0.0 blocked.example.com
127.0.0.1 tracker.example.com
127.10.20.30 ads.example.com

# 公网 IP hosts，归入白名单
8.8.8.8 allowed.example.com

# 其他非公网 IP hosts 在清洗时丢弃
192.168.1.1 private.example.com
::1 ipv6-loopback.example.com

# AdGuard 黑白名单
||ads.example.com^
@@||allowed.example.com^$important
```

输入读取时会忽略空行、规则头部以及以 `!`、`#`、`[` 开头的整行注释。行尾由空白分隔的 `!` 或 `#` 注释也会被移除。

以下内容不会进入 AdGuard Home 域名输出：

- 无法解析为合法域名的条目；
- `localhost`、`localhost.localdomain` 和纯 IP；
- URL 路径规则、正则规则、元素隐藏规则等非域名规则（仍会按兼容性进入浏览器扩展订阅）；
- 不属于纯域名、双字段 hosts 或 AdGuard `||` 域名锚点格式的内容。

hosts 规则在进入浏览器兼容文件和 AdGuard Home 文件前，都会执行以下清洗判定：

- IPv4 `0.0.0.0` 和 `127.0.0.0/8`（所有 `127.*.*.*`）视为有效黑名单；
- 指向公网 IPv4 或 IPv6 地址的 hosts 规则视为有效白名单；
- 其他非公网地址均视为无效并丢弃，包括未指定地址、私网、链路本地、保留地址以及 IPv6 回环地址；
- 公网判定使用 Python `ipaddress` 模块的 `is_global` 结果。

## 处理流程

```text
读取本地规则和远程来源
        ↓
移除注释、空行并按原始规则精确去重
        ↓
识别纯域名 / hosts / AdGuard 格式
        ↓
域名小写化、尾点处理及有效性校验
        ↓
丢弃非 0.0.0.0、非 127/8 且非公网 IP 的 hosts 规则
        ↓
白名单优先解决同域名冲突
        ↓
输出保留有效子域名的浏览器兼容规则
        ↓
精简被父域名覆盖的普通子域名
        ↓
转换为统一 AdGuard 格式并输出最终文件
```

同一个域名同时出现在黑名单和白名单时，将从最终黑名单中移除并保留在白名单中。黑白名单内部若同时存在 `example.com` 和 `sub.example.com`，最终仅保留父域名 `example.com`。以 `*.` 开头的通配符域名不参与普通父子域精简。

## 输出说明

| 文件 | 处理程度 | 输出格式 |
| --- | --- | --- |
| `BlackList_Raw.txt` | 已过滤无效 hosts、标准化、解决冲突并去重；保留有效子域名，不做层级精简 | `||example.com^` |
| `WhiteList_Raw.txt` | 已过滤无效 hosts、标准化、解决冲突并去重；保留有效子域名，不做层级精简 | `@@||example.com^` |
| `BlackList.txt` | 已过滤无效 hosts、标准化、解决冲突、精简层级并去重 | `||example.com^` |
| `WhiteList.txt` | 已过滤无效 hosts、标准化、解决冲突、精简层级并去重 | `@@||example.com^$important` |
| `AdGuardHome.txt` | 合并层级精简后的 AdGuard Home 黑白名单 | `||example.com^` / `@@||example.com^$important` |

四个文件均按标准化域名字典序排列。Raw 文件名为兼容已有订阅链接而保留，其内容已经清洗，不再代表未经处理的原始规则。

- 清洗规则 `BlackList.txt` 和 `WhiteList.txt`：适用于 AdGuard Home。
- 浏览器兼容规则 `BlackList_Raw.txt` 和 `WhiteList_Raw.txt`：适用于 AdGuard、Adblock Plus 及支持 Adblock 过滤语法的浏览器插件。

### 浏览器扩展专用订阅

| 文件 | 目标扩展 | 规则处理方式 |
| --- | --- | --- |
| `AdGuard.txt` | AdGuard 浏览器扩展 | 保留通用网络与元素隐藏规则以及 AdGuard 扩展语法，排除 uBO 专属语法 |
| `AdblockPlus.txt` | Adblock Plus | 保留 ABP 通用网络规则、URL 掩码和基础元素隐藏规则，排除 AdGuard/uBO 扩展语法及不兼容修饰符 |
| `uBlockOrigin.txt` | uBlock Origin | 保留通用规则以及 uBO 的 scriptlet、程序化元素过滤、重定向和参数移除等扩展语法 |

三个文件分别使用目标扩展的订阅头和规范化写法，只有 Adblock Plus 文件使用 `[Adblock Plus 2.0]` 标识。纯域名和有效 hosts 会转换为 `||domain^` 或 `@@||domain^`；裸域名 URL 掩码统一补充 `||` 锚点；修饰符别名会转换为目标扩展的标准名称。无法无损转换到目标语法的扩展规则会被排除，不会与其他扩展的专属语法混写。例如输入 `csdnimg.cn^*#/preview/` 会规范化为 `||csdnimg.cn^*#/preview/`，进入三个浏览器订阅，但不会进入仅接受域名的 AdGuard Home 文件。

每种浏览器扩展还会生成独立的 `BlackList` 和 `WhiteList` 文件。以 `@@` 开头的网络例外规则，以及使用 `#@#`、`#@$#`、`#@%#`、`#@?#` 的元素隐藏或扩展例外规则进入白名单；其余规则进入黑名单。合并订阅继续保留，用于兼容已有链接。

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

## Python 对外接口

自动程序可直接导入 `RuleProcessor`，调用 `run()` 执行完整流程：

```python
from script import RuleProcessor

processor = RuleProcessor(
    root="/path/to/AdGuardHome-rules",
    timeout=30,
    logger=None,
)
result = processor.run(download=True)

print(result.merged_rules)
print(result.blacklist_rules)
print(result.whitelist_rules)
print(result.discarded_non_public_hosts)
print(result.output_files)
```

构造参数：

- `root`：项目根目录，默认为 `script.py` 所在目录；
- `timeout`：每个远程来源的下载超时秒数；
- `logger`：日志回调，默认为 `print`，传入 `None` 可静默运行。

`run(download=True)` 会生成四份输出并返回不可变的 `ProcessingResult`。传入 `download=False` 时仅处理本地规则，适合测试或离线自动任务。

## 自动更新

`.github/workflows/scheduled-run.yml` 支持以下触发方式：

- 每 8 小时自动运行一次；
- 在 GitHub Actions 页面手动触发。

自动任务使用 Python 3.11 校验 `input/urls.json`，再通过 `RuleProcessor().run(download=True)` 类接口生成规则。任务只暂存 `output/`，并由 `github-actions[bot]` 提交规则变化，不会意外提交其他工作区文件。

## jsDelivr 加速链接

### 浏览器兼容规则

- [BlackList_Raw.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList_Raw.txt)
- [WhiteList_Raw.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList_Raw.txt)

### 浏览器扩展专用规则

- [AdGuard.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuard.txt)
- [AdblockPlus.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdblockPlus.txt)
- [uBlockOrigin.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/uBlockOrigin.txt)
- [AdGuard_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuard_BlackList.txt)
- [AdGuard_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuard_WhiteList.txt)
- [AdblockPlus_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdblockPlus_BlackList.txt)
- [AdblockPlus_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdblockPlus_WhiteList.txt)
- [uBlockOrigin_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/uBlockOrigin_BlackList.txt)
- [uBlockOrigin_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/uBlockOrigin_WhiteList.txt)

### 清洗规则

- [BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/BlackList.txt)
- [WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/WhiteList.txt)
- [AdGuardHome.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuardHome.txt)

jsDelivr 存在短暂缓存延迟。仓库更新后若未立即获取到新内容，请稍后重试。

## 规则来源与致谢

本项目 `input/urls.json` 中使用的规则来自以下项目。部分下载 URL 指向 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 的定时同步文件，该仓库负责汇集、转换及更新规则；规则的原始版权与署名仍归各上游项目及其作者、贡献者所有。

| 使用的规则 | 源仓库或官方网站 | 作者 / 维护者说明 |
| --- | --- | --- |
| AdGuard DNS filter | [AdguardTeam/AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | AdGuard 团队及社区贡献者 |
| EasyList China | [easylist/easylistchina](https://github.com/easylist/easylistchina) | EasyList China 维护团队及社区贡献者 |
| 1Hosts (Lite) | [badmojr/1Hosts](https://github.com/badmojr/1Hosts) | badmojr 及项目贡献者 |
| StevenBlack hosts | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | Steven Black 及各上游列表维护者、贡献者 |
| EasyPrivacy | [easylist/easylist](https://github.com/easylist/easylist) | EasyList / EasyPrivacy 维护团队及社区贡献者 |
| CJX's Annoyance List | [cjx82630/cjxlist](https://github.com/cjx82630/cjxlist) | CJX（cjx82630）及项目贡献者 |
| EasyList | [easylist/easylist](https://github.com/easylist/easylist) | EasyList 维护团队及社区贡献者 |
| AdAway Default Blocklist | [AdAway/AdAway](https://github.com/AdAway/AdAway) | AdAway 项目维护者、hosts 列表维护者及社区贡献者 |
| OISD | [OISD 官方网站](https://oisd.nl/) | OISD 维护者及其所收录的各上游列表作者 |

衷心感谢上述作者、维护团队及所有贡献者长期维护并公开这些规则。本项目仅对规则进行下载、合并、去重、清洗和格式转换，不主张对上游规则内容的所有权；使用规则时请同时遵守各源项目的许可协议及使用条款。

如本项目对相关规则的引用、处理或发布侵犯了您的合法权益，请通过本仓库的 [Issues](https://github.com/IMAiCool/AdGuardHome-rules/issues) 联系，并附上权利证明及相关规则信息；核实后将及时删除或调整。

## 注意事项

- `BlackList_Raw.txt` 和 `WhiteList_Raw.txt` 仅包含通用域名锚点语法；需要 URL 路径、正则、元素隐藏或扩展专属语法时，应订阅对应的浏览器扩展专用文件。
- 白名单中使用 `$important`，用于提高例外规则的优先级。
- 上游规则的内容和可用性由各自维护者负责；下载失败的来源应在 `input/urls.json` 中及时更新。
- 排查误拦截时，可先检查保留完整有效子域名的浏览器兼容文件，再与层级精简后的 AdGuard Home 文件对照。
