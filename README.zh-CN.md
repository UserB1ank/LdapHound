# LdapHound

[English](./README.en.md) | **简体中文**

> ADExplorer `.dat` 快照的离线分析工具——解析、浏览、审计 Active Directory 的
> ACL 关系，全程不接触域控。

## 简介

LdapHound 直接解析 Sysinternals ADExplorer 导出的 `.dat` 二进制快照文件，
重建 AD 目录树（Domain / Configuration / Schema 三个 naming context），并展示
每个对象的属性与 ACL（DACL/ACE）。所有解析在本地完成，不需要连接域控，适合：

- 事后审计已下线的 AD 快照
- 攻防演练 / CTF 中的 AD 数据复盘
- BloodHound 数据的离线补充
- ADExplorer 快照格式的逆向研究

## 功能

### 解析库（`ldaphound-core`）

- 完整解析 ADExplorer `.dat` 格式（Header / Properties / Objects / Classes）
- 解码所有常见 `ads_type`：String / Integer / LargeInteger / OctetString /
  Boolean / UTCTime / NT_SECURITY_DESCRIPTOR
- SID（注意 `IdentifierAuthority` 是大端）、GUID（混合字节序）解析
- SecurityDescriptor / ACL / ACE 完整解码，支持
  `ACCESS_ALLOWED` / `ACCESS_DENIED` / `ACCESS_ALLOWED_OBJECT` /
  `ACCESS_DENIED_OBJECT` 等 ACE 类型
- AccessMask 位掩码解码 + 扩展权限 GUID 映射（DCSync / WriteMember /
  WriteSPN / RBCD 等高价值权限自动识别）
- 目录树构建：按 DN 推导父子关系，三个 NC 根自动识别
- LDAP 搜索过滤器（RFC 4515 子集）：`(&...)`、`(|...)`、`(!...)`、
  `(attr=value)`、`(attr>=value)`、`(attr=pre*fix)`、`(attr=*)`
  - `objectCategory` 友好匹配：DN 形式（`CN=Person,CN=Schema,...`）与短名
    （`Person`）等价
- 内存映射 + 后台线程解析，4GB+ 快照也能保持 UI 响应

### 命令行（`ldaphound-cli`）

```bash
# 列出所有对象（ldapsearch 风格）
ldaphound-cli snapshot.dat

# 按索引 / DN / SID 查看单个对象的 ACL 详情
ldaphound-cli snapshot.dat --object "CN=Administrator,CN=Users,DC=x"
ldaphound-cli snapshot.dat --object S-1-5-21-...-519

# 按类型过滤（可重复，OR 关系）
ldaphound-cli snapshot.dat --type user --type computer

# LDAP 过滤器（与 --type AND 组合）
ldaphound-cli snapshot.dat --filter '(&(objectCategory=Person)(objectClass=User))'
ldaphound-cli snapshot.dat --filter '(sAMAccountName=j*)'
```

输出为 ldapsearch 风格（`dn:` + `attribute: value`），便于管道处理。

### 图形界面（`ldaphound-gui`）

基于 iced 0.14 + iced_aw，参考 halloy 客户端的布局：

- **顶部菜单栏**：Open .dat 按钮 + 状态栏
- **左侧目录树**：递归渲染三个 NC，支持展开/折叠、按 DN/名称子串过滤、
  按对象类型显示图标（用户、计算机、容器等）
- **可拖动分隔条**：sidebar 与主窗格之间可拖动调整宽度（pane_grid）
- **主窗格 TitleBar**：显示对象图标 + 名称 + class + DN
- **属性 / ACL 双标签页**：
  - Attributes：按属性名字母序排列
  - ACL：每个 ACE 渲染为独立卡片（#/Kind/Right/Mask/Inherited/Trustee），
    长文本可水平滚动，行内字段可拖动选中 + Ctrl+C 复制
- **ACL trustee 解析**：自动把 SID 反查为对象的 `sAMAccountName` 等识别名
- **Bootstrap Icons 图标字体**内嵌，深色主题

## 项目结构

```
LdapHound/
├── crates/
│   ├── ldaphound-core/        # 解析库（无 GUI 依赖，可独立测试）
│   │   └── src/
│   │       ├── snapshot/      # dat 解析（Header/Property/Object/Attribute）
│   │       ├── security/      # SD/ACL/ACE/AccessMask/ObjectTypeGUID
│   │       ├── filter.rs      # LDAP 搜索过滤器解析与求值
│   │       ├── tree.rs        # 目录树构建
│   │       ├── dump.rs        # ldapsearch 风格输出
│   │       ├── sid.rs / guid.rs
│   │       └── bin/cli.rs     # 命令行入口
│   └── ldaphound-gui/         # iced 图形界面
│       └── src/
│           ├── app.rs         # 状态机 + Elm update/view
│           ├── view/          # sidebar + object_view
│           ├── theme.rs       # 调色板 + 按钮/容器样式
│           └── icon.rs        # Bootstrap Icons 字形
├── docs/
│   └── snapshot-format.md     # .dat 格式规范（实测校准）
└── Cargo.toml                 # workspace
```

## 构建

需要 Rust 1.85+（edition 2024）。

```bash
# 构建所有
cargo build --release

# 运行 GUI
cargo run --release -p ldaphound-gui

# 运行 CLI
cargo run --release -p ldaphound-core --bin ldaphound-cli -- snapshot.dat
```

## 测试

```bash
cargo test -p ldaphound-core --lib
```

覆盖：SID/GUID 字节解析、Header 字段偏移、LDAP 过滤器解析与求值（含
`objectCategory` DN 友好匹配）、目录树构建。

## 背景

ADExplorer `.dat` 格式是 Microsoft 的私有二进制格式，无官方文档。本项目的格式
依据来自 [`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py)
（MIT 协议，c3c 的工作）的逆向，并参考了 [MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/)
公开规范。解析器是 clean-room 实现，不引用任何上述项目的代码。

详细的格式规范见 [`docs/snapshot-format.md`](./docs/snapshot-format.md)，
包含字段偏移表和实测校准数据。

## 许可证

MIT。详见 [LICENSE](./LICENSE)。

Bootstrap Icons 字体（`assets/bootstrap-icons.ttf`）按其自身的 MIT 许可证使用。
