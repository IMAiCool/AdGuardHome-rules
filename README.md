
# AdGuardHome规则合并去重

---

## 一、项目简介

本项目为一套Python脚本，旨在自动化处理AdGuard及相关规则列表的下载、合并、分类、去重和格式化。  
支持从多个上游规则源和本地规则文件同步内容，统一规范化规则格式，检测并处理黑白名单冲突及域名层级冲突，最终输出标准化黑白名单文件，方便后续在AdGuardHome使用。

---

## 二、功能模块说明

### **第一步：下载与初步清洗规则**

* **输入**：
  
  * 本地规则：`./input/local-rules.txt`
  
  * 上游规则链接：`./input/urls.conf`

* **处理**：
  
  * 去除所有注释（包含! #及其之后所有内容，! #为行首或者前面有空格）
  
  * 下载上游规则，提取有效规则（以 `@`, `|`, `127.0.0.1`, `0.0.0.0`, `::` 开头，且不包含特殊字符）。

* **输出**：
  
  * 无用条目 → `./Merge-rule/merge_others.txt`
  
  * 有用条目 → `./Merge-rule/merge_rules.txt`

* * *

### **第二步：规则分类**

* **规则类型**：
  
  * 纯 hosts：IP 域名
  
  * 标准 AdGuard 规则：以 `||` 和 `@@` 开头的各种组合
  
  * 纯域名：如 `example.com`
  
  * 其他不符合的

* **输出目录**：`./Classification/` 目录下分别输出四类规则

* * *

### **第三步：黑白名单分类**

* **hosts 文件**：
  
  * 黑名单：IP 为 `0.0.0.0` `127.0.0.1` `::`
  
  * 白名单：其他

* **AdGuard 文件**：
  
  * 黑名单：`||` 开头
  
  * 白名单：`@@` 开头

* **输出目录**：`./BAWLC/`

* * *

### **第四步：格式剥离**

* **目标**：提取出纯域名，便于后续处理

* **输入来源**：
  
  * `hosts-black.txt`、`adguard-black.txt`、`adguard-white.txt`

* **输出目录**：`./stripping_rules/`

* **控制台信息**：剥离结果数量

* * *

### **第五步：初步合并黑白名单**

* **黑名单合并**：
  
  * `hosts-domain.txt` + `adguard-bdomain.txt` → `BlackList_tmp.txt`

* **白名单初步处理**：
  
  * 提取一级域名 → `white_2d.txt`
  
  * 其余输出 → `WhiteList_tmp.txt`

* **输出目录**：`./ipombaw/`

* * *

### **第六步：冲突处理**

* **处理两个维度冲突**：
  
  1. **黑白名单冲突**：同一条目出现在黑白名单,再黑名单查找是否有上级域名，如果没有，则将其从两个名单中剔除，反之则仅从黑名单删除
  
  2. **层级冲突**：同一名单中，域名及其下属域名不能共存，如 `example.com` 与 `a.b.example.com` 共存,则删除` a.b.example.com` 

* **输出**：
  
  * 冲突日志：`./Log/Conflict_handling.log`, `./Log/Hierarchy_conflict.log`
  
  * 去重后黑白名单：`./output/AdBlackList.txt`, `./output/AdWhiteList.txt`

* * *

### **第七步：格式标准化**

* **内容校验**：
  
  * 删除 `localhost`、纯 IP 条目

* **格式转换(按使用需要,这里转换为adguard格式)**：
  
  * 白名单 → `@@||example.com^$important`
  
  * 黑名单 → `||example.com^`

* **添加头部信息**

* **输出目录**：`./output/AdGuardHomeBlack.txt` 和 `AdGuardHomeWhite.txt`


## 三、目录结构

```
main/
│
├─ input/              # 输入文件目录
│   ├─ urls.conf         # 远程规则URL列表，格式：规则名: URL
│   └─ local-rules.txt   # 本地规则文件
│
├─ Classification/               # 根据格式分类存储目录
│   ├─ adguard-rules.txt
│   ├─ hosts
│   ├─ others.txt
│   └─ domain.txt
│
├─ BAWLC/               # 黑白名单分类
│   ├─ adguard-black.txt
│   ├─ adguard-white.txt
│   ├─ hosts_black.txt
│   └─ hosts_white.txt
│
├─ Log/                  # 日志文件目录
│   ├─ both-in-white-and-black.log       # 黑白名单冲突日志
│   └─ Hierarchy_conflict.log      # 域名层级冲突删除日志
│
├─ output/               # 最终输出目录
│   ├─ AdGuardHomeBlack.txt    # 格式化黑名单最终文件
│   └─ AdGuardHomeWhite.txt    # 格式化白名单最终文件
│
└─ *.py             # 脚本文件，包含所有功能模块及主函数
```

---

## 四、运行说明

1. 将远程规则URL列表放入 `./input/urls.conf` ，格式为 `规则名: URL`
2. 本地规则放入 `./input/local-rules.txt`
3. 运行 `python script.py`或者`python3 script.py`
4. 脚本执行完成后，中间文件输出于 `./others/`，日志输出于 `./Log/`，最终黑白名单分别输出到 `./output/`
5. 查看日志文件确认冲突及层级冲突详情

---

## 五、注意事项

- 确保执行脚本的目录存在上述目录结构或提前创建
- 保证网络畅通以正确下载远程规则
