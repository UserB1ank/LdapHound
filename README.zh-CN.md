# LdapHound

[English](./README.md) | **简体中文**

> 深度解析 Active Directory **安全描述符（Security Descriptor）** 的离线工具——
> 直接读取 ADExplorer `.dat` 快照，无需连接域控。同时提供 GUI 与 CLI。

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

## 使用方法 —— GUI

```bash
cargo run --release -p ldaphound-gui
```

- 顶部菜单栏：**Open .dat**
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
# 列出所有对象（ldapsearch 风格输出）
ldaphound-cli snapshot.dat

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
