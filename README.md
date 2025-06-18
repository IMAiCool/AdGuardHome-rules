# AdGuardHome规则合并去重

---

## 一、项目简介

支持从多个上游规则源和本地规则文件同步内容，合并去重，检测并处理黑白名单冲突及域名层级冲突，统一格式化规则，最终输出标准化黑白名单文件。
本人仅用于AdGuardHome，所以许多AdGuardHome无法使用的被并于无效条目。

---

## 二、处理步骤说明

### **第一步：下载与初步清洗规则**

* **输入**：
  
  * 本地规则：`./input/local-rules.txt`
  
  * 上游规则链接：`./input/urls.conf`

* **处理**：
  
  * 去除所有注释（包含! #及其之后所有内容，! #为行首或者前面有空格）
  
  * 下载上游规则，提取有效规则。

* **分类输出**：
  
  * 无效条目
  
  * 有效条目

* * *

### **第二步：规则分类**

* **规则类型**：
  
  * 纯 hosts：IP 域名
  
  * 标准 AdGuard 规则：以 `||` 和 `@@` 开头的各种组合
  
  * 纯域名：如 `example.com`
  
  * 其他不适用上述分类的

* * *

### **第三步：黑白名单分类**

* **hosts 文件**：
  
  * 黑名单：IP 为 `0.0.0.0` `127.0.0.1` `::`
  
  * 白名单：其他

* **AdGuard 文件**：
  
  * 黑名单：`||` 开头
  
  * 白名单：`@@` 开头

* * *

### **第四步：格式剥离**

* **目标**：提取出纯域名，便于后续处理

* **输入来源**：
  
  * `hosts-black.txt`、`adguard-black.txt`、`adguard-white.txt`

* * *

### **第五步：初步合并黑白名单**

* **黑名单合并**：
  
  * `hosts-domain.txt` + `adguard-bdomain.txt` → `BlackList_tmp.txt`

* **白名单初步处理**：

* * *

### **第六步：冲突处理**

* **处理两个维度冲突**：
  
  1. **黑白名单冲突**：同一条目出现在黑白名单,在黑名单查找是否有上级域名，如果没有，则将其从两个名单中剔除，反之则仅从黑名单删除
  
  2. **层级冲突**：同一名单中，域名及其下属域名不能共存，如 `example.com` 与 `a.b.example.com` 共存,则删除` a.b.example.com` 

* * *

### **第七步：格式标准化**

* **内容校验**：
  
  * 删除 `localhost`、纯 IP 条目

* **格式转换(按使用需要,这里转换为adguard格式)**：
  
  * 白名单 → `@@||example.com^$important`
  
  * 黑名单 → `||example.com^`

* **添加头部信息**


## 三、目录结构

```
main/
│
├─ input/              # 输入文件目录
│   ├─ urls.conf         # 远程规则URL列表，格式：规则名: URL
│   └─ local-rules.txt   # 本地规则文件
├─ temp/              # 中间处理文件目录
├─ output/               # 最终输出目录
│   ├─ BlackList.txt    # 格式化黑名单最终文件
│   └─ WhiteList.txt    # 格式化白名单最终文件
│
└─ *.py             # 脚本文件，包含所有功能模块及主函数
```

---

## 四、运行说明

1. 将远程规则URL列表放入 `./input/urls.conf` ，格式为 `规则名: URL`
2. 本地规则放入 `./input/local-rules.txt`
3. 运行 `python script.py`或者`python3 script.py`
4. 脚本执行完成后，中间文件及日志输出 `./temp/`，最终黑白名单分别输出 `./output/`
5. 查看日志文件确认冲突及层级冲突详情

---
## 五、直达链接
**白名单**

    https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@refs/heads/main/output/WhiteList.txt

**黑名单**

    https://cdn.jsdelivr.net/gh/IMAiCool/AdGuardHome-rules@refs/heads/main/output/BlackList.txt



---
## 六、注意事项

- 确保执行脚本的目录存在上述目录结构或提前创建
- 保证网络畅通以正确下载远程规则
