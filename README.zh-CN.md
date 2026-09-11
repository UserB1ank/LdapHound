# LdapHound

[English](./README.md) | **简体中文**

> 深度解析 Active Directory **安全描述符（Security Descriptor）** 的离线工具——
> 直接读取 ADExplorer `.dat` 快照或 `ldapsearch` LDIF 导出，无需连接域控。
> 同时提供 GUI 与 CLI。

![1](docs\1.png)

## 项目作用

LdapHound 读取 Sysinternals ADExplorer 导出的 `.dat` 二进制快照，完整重建
每个对象的 **nTSecurityDescriptor**：Owner/Group SID、Control Flags、
DACL/SACL，以及每一条 ACE。安全描述符是 AD 访问控制的核心——LdapHound 把
原始的自相对二进制 blob 转成可读、可审计的结构。

- 解码所有常见 ACE 类型：`ACCESS_ALLOWED`、`ACCESS_DENIED`、
  `ACCESS_ALLOWED_OBJECT`、`ACCESS_DENIED_OBJECT`，以及原始的
  `SYSTEM_AUDIT` 系列
- 拆解 AccessMask 位字段（GenericAll / WriteDACL / WriteOwner /
  ExtendedRight / WriteProperty / ...），并把扩展权限 GUID 映射到名称——
  DCSync、WriteMember、WriteSPN、UserForceChangePassword、
  WriteAllowedToAct（RBCD）、Enroll 等
- 把 ACE 委托方 SID 反查回快照对象的 `sAMAccountName` / 显示名，
  让权限读作 "Administrators [group]" 而不是裸 SID
- 一眼可见 inherited 与 explicit 的区分、DACL 是否受保护

除 SD 解析外，LdapHound 还重建目录树（Domain / Configuration / Schema 三个
naming context）、解码常见 `ads_type` 属性（String / Integer / OctetString /
SID / GUID / UTCTime），并支持 RFC 4515 LDAP 搜索过滤器
（`(&(objectCategory=Person)(objectClass=User))`、`(sAMAccountName=j*)`）。

同样的视图也适用于 `ldapsearch` 查询结果：把 LDIF 输出保存成文件直接打开——
见 [导入 `ldapsearch` 查询结果](#导入-ldapsearch-查询结果ldif)。

## 导入 `ldapsearch` 查询结果（LDIF）

LdapHound 可以直接打开 OpenLDAP `ldapsearch`（及兼容工具）写出的 LDIF 文件，
树、属性、ACL 视图与 `.dat` 快照完全一致。输入格式自动检测：GUI 的
**Open…** 和 CLI 都同时接受两种文件。

### 推荐查询语法

```bash
ldapsearch -o ldif-wrap=no -E pr=1000/noprompt \
  -x -H ldap://dc01.corp.local -D 'CORP\jdoe' -W \
  -b 'DC=corp,DC=local' \
  '(objectClass=*)' '*' nTSecurityDescriptor \
  > corp.ldif
```

各参数说明：

| 参数 | 说明 |
| --- | --- |
| `-E pr=1000/noprompt` | **必加。** AD 单页最多返回 1000 条，必须用分页才能导全量数据。 |
| `'*' nTSecurityDescriptor` | `*` 请求全部用户属性；`nTSecurityDescriptor` 必须显式列出，否则 ACL 标签页为空。 |
| `-o ldif-wrap=no` | 让几 KB 的安全描述符保持在单行。可省略——折行同样支持。 |
| `-t` / `-T` | **不要使用。** 二进制属性会被写到临时文件而不是内联 base64，导入器无法读取。 |

二进制属性（`objectSid`、`objectGUID`、`nTSecurityDescriptor` 等）会以
base64 形式返回（`objectSid:: AQAA...`），LdapHound 自动解码。如果安全
描述符为空，说明绑定账号缺少对这些对象的 `READ_CONTROL` 权限。

大域场景下只请求 LdapHound 需要的属性，传输明显更快：

```bash
ldapsearch -o ldif-wrap=no -E pr=1000/noprompt \
  -x -H ldap://dc01.corp.local -D 'CORP\jdoe' -W \
  -b 'DC=corp,DC=local' \
  '(objectClass=*)' \
  objectClass cn name sAMAccountName member memberOf objectSid objectGUID nTSecurityDescriptor \
  > corp.ldif
```

这组属性覆盖：目录树（`objectClass` + 每条记录必带的 `dn:`）、委托方解析
（`objectSid` + `sAMAccountName`/`name`）、ACL 标签页
（`nTSecurityDescriptor`）；`member`/`memberOf` 为可选补充。

缩小范围同理——用 `-b` 或 LDAP 过滤器限制：

```bash
# 只要用户和计算机对象
... -b 'DC=corp,DC=local' '(|(objectCategory=Person)(objectCategory=Computer))' ...
# 只要某个 OU
... -b 'OU=Sales,DC=corp,DC=local' '(objectClass=*)' ...
```

Configuration 与 Schema 两个 naming context 可以单独导出后**拼接到同一个
文件**里——LDIF 记录是自描述的：

```bash
ldapsearch ... -b 'CN=Configuration,DC=corp,DC=local' '(objectClass=*)' '*' nTSecurityDescriptor >> corp.ldif
```

Kerberos 认证（用 `-Y GSSAPI` 替代 `-x -D ... -W`）和 LDAPS
（`ldaps://dc01.corp.local` 或 `-ZZ`）按常规用法即可。

之后像任何快照一样分析：

```bash
ldaphound-cli corp.ldif --type user
ldaphound-cli corp.ldif --object "CN=Administrator,CN=Users,DC=corp,DC=local"
```

## AI 关系图谱分析

LdapHound 可以通过 OpenAI Responses API 的
[函数调用](https://developers.openai.com/api/docs/guides/function-calling)，
向模型提供一个有边界、只读的 LDAP 关系图。模型可以搜索节点、查看节点、
遍历邻居、查找路径和列出高风险关系，但不会直接收到原始快照。

当前图谱包含：

- 目录包含关系和组成员关系（包括 `primaryGroupID`）
- `manager` / `managedBy`、对象所有权、GPO 链接和 SID History
- 带权限名、掩码和继承信息的允许/拒绝 ACL 关系
- 基于资源的约束委派（RBCD）与约束委派 SPN

API 密钥只通过进程环境变量提供：

```bash
export OPENAI_API_KEY='...'
# 可选，默认使用 gpt-5.6
export OPENAI_MODEL='gpt-5.6'

ldaphound-cli snapshot.dat --ai "查找通向高权限组的高风险路径"
ldaphound-cli snapshot.dat --ai "分析这个账号" --ai-focus 'CORP\\jdoe'
```

GUI 在所选对象的 **AI Analysis** 标签页提供相同功能。只有点击
**Analyze graph** 后才会访问模型服务。

### 隐私边界

- API 请求设置 `store: false`；密钥不会进入应用状态、文件、图谱导出、
  提示词或日志。
- 不上传原始 `.dat`/LDIF、原始安全描述符、二进制值或任意 LDAP 属性；
  工具仅返回长度受限的身份、安全状态和关系字段。
- LDAP 值全部视为不可信数据，属性中的文本不会被当作模型指令执行。
- 发起请求前可以导出并检查 AI 工具实际能够暴露的全部数据：

```bash
ldaphound-cli snapshot.dat --export-ai-graph ai-graph.json
```

名称、DN、SID、选定的安全属性和图关系本身仍属于目录数据；模型请求这些
字段时会发生传输。请使用组织批准的 API 项目和数据处理策略。

## 使用方法 —— GUI

```bash
cargo run --release -p ldaphound-gui
```

- 顶部菜单栏：**Open…**——ADExplorer `.dat` 快照或 LDAP/LDIF 导出
  （格式自动检测）
- 左侧目录树：三个 naming context 的递归树，支持展开/折叠、子串过滤、
  按对象类型显示图标
- 主窗格：对象 TitleBar（图标 + 名称 + class + DN），下方两个标签页
  - **Attributes**：按属性名排序的 name|value 列表
  - **ACL**：每个 ACE 渲染为独立卡片（#/Kind/Right/Mask/Inherited/Trustee）。
    长内容可水平滚动；卡片内字段可拖动选中 + Ctrl+C 复制。选中卡片会显示
    Copy 按钮，复制整行 tab 分隔文本。
- sidebar 与主窗格之间有可拖动的分隔条

## 使用方法 —— CLI

```bash
# 列出所有对象（ldapsearch 风格输出）；输入可以是 ADExplorer .dat 快照，
# 也可以是 ldapsearch LDIF 导出（自动检测）
ldaphound-cli snapshot.dat
ldaphound-cli corp.ldif

# 通过隐私受限的关系图谱进行 AI 分析
ldaphound-cli snapshot.dat --ai "查找危险的委派权限"

# 查看单个对象的完整安全描述符 + ACL 详情
ldaphound-cli snapshot.dat --object "CN=Administrator,CN=Users,DC=x"
ldaphound-cli snapshot.dat --object S-1-5-21-...-519

# 按类型过滤（可重复，OR 关系）
ldaphound-cli snapshot.dat --type user --type computer

# LDAP 过滤器（与 --type AND 组合）
ldaphound-cli snapshot.dat --filter '(&(objectCategory=Person)(objectClass=User))'
ldaphound-cli snapshot.dat --filter '(sAMAccountName=j*)'
```

输出为 ldapsearch 风格（`dn:` + `attribute: value`），便于管道处理。

## 构建与测试

需要 Rust 1.85+（edition 2024）。

```bash
cargo build --release
cargo test  -p ldaphound-core --lib
```

## 背景

ADExplorer `.dat` 格式无官方文档，属于私有二进制格式。格式知识来自
[`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py)
（MIT 协议，c3c 的逆向工作），并参考了
[MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/)
公开规范。解析器是 clean-room 实现，未引用上述任何项目的代码。完整格式规范
（含字段偏移表与实测校准数据）见
[`docs/snapshot-format.md`](./docs/snapshot-format.md)。

## 许可证

MIT。内嵌的 Bootstrap Icons 字体保留其自身的 MIT 许可证。
