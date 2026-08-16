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
│  ├─ AdGuardHome_BlackList.txt / AdGuardHome_WhiteList.txt
│  ├─ AdGuard_BlackList.txt / AdGuard_WhiteList.txt
│  ├─ AdblockPlus_BlackList.txt / AdblockPlus_WhiteList.txt
│  ├─ uBlockOrigin_BlackList.txt / uBlockOrigin_WhiteList.txt
│  └─ ElementRules.txt           # 元素隐藏与 scriptlet 独立规则
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

hosts 规则在进入各目标输出前，都会执行以下清洗判定：

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
按 AdGuard、Adblock Plus、uBlock Origin 标准分别校验并格式化
        ↓
精简被父域名覆盖的普通子域名
        ↓
按目标产品分别输出黑名单与白名单
```

同一个域名同时出现在黑名单和白名单时，将从最终黑名单中移除并保留在白名单中。黑白名单内部若同时存在 `example.com` 和 `sub.example.com`，最终仅保留父域名 `example.com`。以 `*.` 开头的通配符域名不参与普通父子域精简。

## 输出说明

脚本只生成下表中的 8 个正式订阅。每份文件只包含对应产品认可的标准语法；来源注释、标题、hosts 原文、其他产品专属语法和无法验证的内容均会删除。

| 目标产品 | 类型 | 输出文件与订阅链接 | 标准格式与用途 |
| --- | --- | --- | --- |
| AdGuard Home | 黑名单 | [AdGuardHome_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuardHome_BlackList.txt) | `||example.com^`，域名级拦截并执行父子域精简 |
| AdGuard Home | 白名单 | [AdGuardHome_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuardHome_WhiteList.txt) | `@@||example.com^$important`，域名级放行 |
| AdGuard | 黑名单 | [AdGuard_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuard_BlackList.txt) | 仅 `||` 开头的 AdGuard 标准域名网络、URL 路径和通配符规则 |
| AdGuard | 白名单 | [AdGuard_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdGuard_WhiteList.txt) | 仅 `@@||` 开头的 AdGuard 网络例外规则 |
| Adblock Plus | 黑名单 | [AdblockPlus_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdblockPlus_BlackList.txt) | 仅 `||` 开头且修饰符受 ABP 支持的网络规则 |
| Adblock Plus | 白名单 | [AdblockPlus_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/AdblockPlus_WhiteList.txt) | 仅 `@@||` 开头的 ABP 网络例外规则 |
| uBlock Origin | 黑名单 | [uBlockOrigin_BlackList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/uBlockOrigin_BlackList.txt) | 仅 `||` 开头并使用 uBO 标准修饰符名称的网络规则 |
| uBlock Origin | 白名单 | [uBlockOrigin_WhiteList.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/uBlockOrigin_WhiteList.txt) | 仅 `@@||` 开头的 uBO 网络例外规则 |
| 浏览器扩展元素规则 | 独立合集 | [ElementRules.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/ElementRules.txt) | 独立保存 `##`、`###`、`#@#`、AdGuard 扩展元素规则及 uBO scriptlet |

纯域名和有效 hosts 会先转换为目标格式；裸域名 URL 掩码会补充 `||` 锚点；修饰符别名会转换为目标产品采用的规范名称。例如 `csdnimg.cn^*#/preview/` 会格式化为 `||csdnimg.cn^*#/preview/`。黑名单正文全部以 `||` 开头，白名单正文全部以 `@@||` 开头。元素隐藏（`##`、`###`、`#@#`）、scriptlet、纯正则、单竖线 URL 规则及无法验证的内容全部删除。

### ElementRules.txt 使用说明

`ElementRules.txt` 与八份网络黑白名单完全隔离，集中保存网页元素隐藏、元素隐藏例外、AdGuard 扩展 CSS 和 uBlock Origin scriptlet。它会删除来源注释、Markdown 标题、空行和无效内容，并按原始规则精确去重。主要标记如下：

| 标记示例 | 用途 |
| --- | --- |
| `##.advert`、`###advert` | 隐藏匹配 CSS class 或 ID 的网页元素 |
| `example.com##.advert` | 仅在指定网站隐藏元素 |
| `example.com#@#.advert` | 在指定网站取消对应的元素隐藏规则 |
| `example.com#$#...`、`example.com#?#...` | AdGuard 扩展 CSS / 扩展选择器规则 |
| `example.com##+js(...)` | uBlock Origin scriptlet 规则 |

使用方式：

1. 先订阅对应产品的网络黑名单与白名单。
2. 浏览器扩展需要页面元素过滤时，再额外订阅 [ElementRules.txt](https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@main/output/ElementRules.txt)。
3. 该文件不适用于 AdGuard Home；AdGuard 与 uBlock Origin 会忽略自身不支持的专属语法，但不同扩展的实际支持范围可能不同。
4. 如果扩展报告规则语法错误，应停用该元素规则订阅，或改用扩展官方提供的专用元素过滤列表。

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

所有正式订阅链接已集中列在“输出说明”表格中。

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

- AdGuard Home 白名单使用 `$important` 提高例外规则优先级；其他产品按各自标准保留或转换例外规则。
- 上游规则的内容和可用性由各自维护者负责；下载失败的来源应在 `input/urls.json` 中及时更新。
- 排查误拦截时，请检查对应产品的白名单，并与同产品黑名单对照。
