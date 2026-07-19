# LdapHound

[English](./README.en.md) | **简体中文**

> Offline inspector for ADExplorer `.dat` snapshots — parse, browse, and audit
> Active Directory ACL relationships without ever touching a domain controller.

---

LdapHound 是一个离线的 ADExplorer 快照分析工具。它直接解析 ADExplorer 导出的
`.dat` 文件，重建 AD 目录树，并展示每个对象的 ACL 关系——全程不需要连接域控，
适合事后审计、攻防演练复盘、BloodHound 数据补全等场景。

详细说明请见 [简体中文文档](./README.zh-CN.md)。
