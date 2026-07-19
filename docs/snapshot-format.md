# ADExplorer Snapshot `.dat` 格式规范

> **目的**：本文档是 LdapHound 解析 ADExplorer 导出的 `.dat` 快照文件的**单一事实源**。所有偏移、字段顺序、值类型均以 `example/ADExplorerSnapshot/adexpsnapshot/parser/structure.py` (MIT, c3c) 的 `dissect.cstruct` 定义为权威依据，并使用 `example/0718.dat` (3.41 MB, DC=`DC01.garfield.htb`, 3624 对象) 实测校准。
>
> 格式本身为 ADExplorer 私有二进制格式（无官方文档），由 Python 版逆向得到。本文档独立重述格式语义，便于 Rust 实现时无需反复回查 Python 代码。

## 0. 总体布局

文件按以下顺序连续排列 5 个段：

```
┌─────────────────────────── offset 0
│  Header                   (固定 1086 字节, 0x000 - 0x43E)
├─────────────────────────── offset 0x43E
│  Objects                  (numObjects 个 Object, 变长)
├─────────────────────────── offset = metadataOffset
│  Properties               (numProperties 个 Property, 变长)
├─────────────────────────── Properties 之后
│  Classes                  (numClasses 个 Class, 变长)
├─────────────────────────── Classes 之后
│  Rights                   (numRights 个 Right, 变长)
├─────────────────────────── offset = treeviewOffset (可选)
│  Treeview                 (可能缺失; 见 treeview 段)
└─────────────────────────── EOF
```

**字段对齐**：所有字段都是**自然对齐**，无显式 padding（除 Objects 与 Properties 之间可能有 ≤16 字节的填充，解析时按绝对 offset seek 即可）。

**字节序**：全部 **小端 (Little Endian)**。

**字符串**：所有字符串是 **UTF-16LE**（cstruct `wchar` = 2 字节/字符）。

### 实测样本 `0718.dat` 的关键 offset

| 段 | 起点 | 备注 |
|---|---|---|
| Header | 0x000 | 1086 字节 |
| Objects | 0x43E | header 之后立即开始 |
| Properties | 0x282665 (= 2631269) | = metadataOffset |
| Treeview | 0x339B4C (= 3382092) | = treeviewOffset |
| EOF | 0x340A74 (= 3412084) | 文件大小 |

`numObjects = 3624`，`numProperties = 1499`，从 `0x43E` 顺序读 3624 个对象到 `0x28265D`，距 `metadataOffset` 仅差 8 字节填充，验证布局正确。

---

## 1. Header (0x000 - 0x43E, 1086 字节)

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0x000 | 10 | `winAdSig` | `char[10]` | 固定签名 `win-ad-ob\x00`，校验文件类型 |
| 0x00A | 4 | `marker` | `i32` | `0x10001`，用途未知 |
| 0x00E | 8 | `filetime` | `u64` | Windows FILETIME (100ns 自 1601-01-01) |
| 0x016 | 520 | `optionalDescription` | `wchar[260]` | 用户描述，常为空 |
| 0x21E | 520 | `server` | `wchar[260]` | DC 主机名 (例 `DC01.garfield.htb`) |
| 0x426 | 4 | `numObjects` | `u32` | Object 段对象总数 |
| 0x42A | 4 | `numAttributes` | `u32` | **实测无意义**，请忽略。属性数以 metadataOffset 处 `numProperties` 为准 |
| 0x42E | 8 | `metadataOffset` | `u64` | Properties 段绝对起点 |
| 0x436 | 8 | `treeviewOffset` | `u64` | Treeview 段绝对起点（可能缺失） |
| 0x43E | — | — | — | **Header 结束，Objects 紧随开始** |

> ⚠️ **Python 版的命名陷阱**：Python `structure.py` 定义了一个 `unk0x43a` (i32) 字段，名字暗示它位于 0x43A。但 `dissect.cstruct` 报告该字段 `offset=1086=0x43E`，且实测 0x43E 处的值就是**第一个对象的 `objSize`**。这是 Python 版的字段命名 bug——它把 Object[0] 的 `objSize` 字段误划入 Header。**Rust 实现请直接把 Objects 段起点定为 `0x43E`**，不要跟随 Python 的 `unk0x43a` 字段。

**filetime → Unix 时间戳转换**：
```rust
// filetime 单位: 100ns, 起点: 1601-01-01 UTC
unix_seconds = (filetime - 116444736000000000) / 10_000_000;
// filetime == 0 或 == i64::MAX 视为"未设置"
```

---

## 2. Object (Objects 段, 每个 Object 变长)

Object 是 AD 域中一个目录条目（用户/组/计算机/OU/...）。所有 Object 紧密排列，每个 Object 的总长度由其内部的 `objSize` 字段决定。

### 2.1 Object 头部

| 字段 | 类型 | 说明 |
|---|---|---|
| `objSize` | `u32` | **本 Object 总字节数**（含本字段、tableSize 字段、mapping 表、属性值 blob） |
| `tableSize` | `u32` | mapping 表条目数（= 该对象拥有的属性数量） |
| `mappingTable` | `MappingEntry[tableSize]` | 见下 |

下一个 Object 起点 = **本 Object 起点 + objSize**。

### 2.2 MappingEntry (8 字节/条)

| 字段 | 类型 | 说明 |
|---|---|---|
| `attrIndex` | `u32` | 该属性在 Properties 段中的索引（0-based） |
| `attrOffset` | `i32` | **有符号**偏移：属性值数据相对本 Object 起点的位置 |

> ⚠️ **关键坑**：`attrOffset` 是 **i32（有符号）**。正值常见，但**负值表示该属性的数据物理上位于前一个对象的 blob 区**（共享存储，ADExplorer 的去重优化）。读取时按如下规则换算为绝对文件 offset：
> ```rust
> let abs = if attr_offset >= 0 {
>     obj_start + attr_offset as u64
> } else {
>     obj_start - (attr_offset.unsigned_abs()) as u64
> };
> ```

### 2.3 属性值区域

紧随 mapping 表之后到 `objSize` 边界之间的字节是**属性值 blob 区**，按 mapping 表的 `attrOffset` 寻址。**不要按顺序读取**，必须 seek 到 `obj_start + attrOffset` 然后按 `ads_type` 解析（见 §3）。

### 2.4 实测样本

`0718.dat` 第一个 Object (起点 0x43E)：
- `objSize = 3076` (0xC04)
- `tableSize = 23`
- mapping 表里多个条目指向同一个 `attrOffset`（如 0x9B2），表示不同属性共享同一个值
- 包含 `nTSecurityDescriptor` (propertyIndex=1153, adsType=25)，DACL 含 17 个 ACE

---

## 3. Attribute Value (按 ads_type 分派)

属性值位于 `obj_start + attrOffset` 处。所有属性都以一个 `u32 numValues` 开头（多值属性的数量），随后按 `ads_type` 不同而布局不同。`ads_type` 来自 Properties 段（见 §4）。

### 3.1 通用头

| 字段 | 类型 |
|---|---|
| `numValues` | `u32` |

### 3.2 按 ads_type 分派表

| `ads_type` | 名称 | 值布局（接在 numValues 之后） |
|---|---|---|
| 1 | `DN_STRING` | 偏移表 `u32[numValues]`（相对**属性起点**），每处指向一个 null-terminated UTF-16LE 字符串 |
| 2 | `CASE_EXACT_STRING` | 同上 |
| 3 | `CASE_IGNORE_STRING` | 同上 |
| 4 | `PRINTABLE_STRING` | 同上 |
| 5 | `NUMERIC_STRING` | 同上 |
| 6 | `BOOLEAN` | `u32[numValues]`，`!=0` 即 true |
| 7 | `INTEGER` | `u32[numValues]`（**注意：DWORD 无符号**） |
| 8 | `OCTET_STRING` | 长度表 `u32[numValues]`，紧随每段原始字节。**SID/GUID 走这里** |
| 9 | `UTC_TIME` | 每 value 16 字节 SYSTEMTIME 结构（见 §3.3） |
| 10 | `LARGE_INTEGER` | `i64[numValues]`（**有符号**；时间戳属性用 Windows FILETIME 单位） |
| 12 | `OBJECT_CLASS` | 同 String（偏移表 + UTF-16） |
| 25 | `NT_SECURITY_DESCRIPTOR` | `u32 lenDescriptorBytes` + `lenDescriptorBytes` 字节（**ACL 数据，GUI 核心**） |
| 其他 | — | 一期不实现，记录为 raw bytes |

> **未实现的 type**：0, 11, 13-24, 26-28 罕见，一期可遇到时报错或当 raw 处理。

### 3.3 SYSTEMTIME (16 字节, ads_type=9)

| 偏移 | 字段 | 类型 |
|---|---|---|
| 0 | `wYear` | `u16` |
| 2 | `wMonth` | `u16` |
| 4 | `wDayOfWeek` | `u16` |
| 6 | `wDay` | `u16` |
| 8 | `wHour` | `u16` |
| 10 | `wMinute` | `u16` |
| 12 | `wSecond` | `u16` |
| 14 | `wMilliseconds` | `u16` |

转 Unix 时间戳时忽略 `wDayOfWeek` 和 `wMilliseconds`。

### 3.4 String 类属性的偏移寻址

ads_type ∈ {1,2,3,4,5,12} 的属性布局：
```
[属性起点]
  u32 numValues
  u32 offsets[numValues]   // 每个 offset 相对【属性起点】, 不是对象起点
[属性起点 + offsets[i]]
  wchar value[]            // UTF-16LE, null-terminated (读到 u16==0 停)
```

读取每个 value 必须 seek 到 `attribute_start + offsets[i]`，读完 seek 回。

### 3.5 OctetString (ads_type=8)

```
[属性起点]
  u32 numValues
  u32 lengths[numValues]
[lengths[i] 字节的原始 buffer]
[lengths[i+1] 字节的原始 buffer]
...
```

值紧凑排列（无偏移表）。**特殊语义**：
- 属性名以 `guid` 结尾且长度=16 → 按 GUID 解析（混合字节序，见 §6）
- 属性名 ∈ {`objectSid`, `securityIdentifier`} → 按 SID 解析（见 §5）

---

## 4. Properties 段 (起点 = metadataOffset)

每个 Property 描述 schema 中一个属性的元信息（名称、类型、GUID）。

### 4.1 Properties 段头

| 字段 | 类型 |
|---|---|
| `numProperties` | `u32` |

### 4.2 Property (变长)

| 字段 | 类型 | 说明 |
|---|---|---|
| `lenPropName` | `u32` | 字节数（不是字符数；= 字符数 × 2） |
| `propName` | `wchar[lenPropName/2]` | 属性名（UTF-16LE, null-terminated） |
| `unk1` | `i32` | 用途未知，实测=4 |
| `adsType` | `u32` | 决定属性值解析方式（见 §3.2） |
| `lenDN` | `u32` | 字节数 |
| `DN` | `wchar[lenDN/2]` | 该属性的 schema DN（例 `CN=Account-Expires,CN=Schema,...`） |
| `schemaIDGUID` | `char[16]` | 16 字节 GUID（混合字节序，§6），用于 ACE 的 ObjectType 解析 |
| `attributeSecurityGUID` | `char[16]` | 16 字节 GUID |
| `blob` | `char[4]` | 4 字节，用途未知 |

### 4.3 实测样本

`0718.dat` Property[0] (起点 0x282669)：
- `propName = "accountExpires"`
- `unk1 = 4`
- `adsType = 10` (LARGE_INTEGER)
- `DN = "CN=Account-Expires,CN=Schema,CN=Configuration,DC=garfield,DC=htb"`
- `schemaIDGUID = 3bf69915-0de6-11d0-a285-00aa003049e2`

Property[1153]：
- `propName = "nTSecurityDescriptor"`
- `adsType = 25` (NT_SECURITY_DESCRIPTOR)

### 4.4 索引映射

Object 的 `mappingTable[i].attrIndex` 是基于 Properties 段顺序的 0-based 索引。建议实现一份 `Vec<Property>` 并按下标访问，同时建一个 `HashMap<propName_lower, index>` 做名称查找（AD 属性名是大小写不敏感的）。

---

## 5. SID 格式 (ads_type=8 的 OctetString 中)

参考 [MS-DTYP §2.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78d440c8-9a5d-4f49-ae88-393206be0a8f)。

| 偏移 | 字段 | 类型 | 说明 |
|---|---|---|---|
| 0 | `Revision` | `u8` | 固定 `1` |
| 1 | `SubAuthorityCount` | `u8` | 后面 SubAuthority 的数量（≤ 8 实际，预留 ≤ 15） |
| 2 | `IdentifierAuthority` | `u8[6]` | 大端 6 字节 |
| 8 | `SubAuthority[]` | `u32[SubAuthorityCount]` | 小端，每个 4 字节 |

字符串形式：`S-<Revision>-<IdentifierAuthority as decimal>-<sub0>-<sub1>...`

例：字节 `01 05 00 00 00 00 00 05 15 00 00 00 2D 41 58 73 C5 BB C0 5D 2A 6D 26 3A 50 04 00 00`
→ `S-1-5-21-1935163693-1572912069-975596842-1104`

> `IdentifierAuthority` 是**大端**读取（不是文件其余部分的小端），是 SID 解析最易错的点。

---

## 6. GUID 格式

参考 [MS-DTYP §2.3.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/e9b6c155-98f8-4e1c-ba86-960edab4f9bf)。GUID 是**混合字节序**（前 3 段小端，后 8 字节大端）。

| 偏移 | 字段 | 长度 | 字节序 |
|---|---|---|---|
| 0 | `Data1` | 4 | 小端 u32 |
| 4 | `Data2` | 2 | 小端 u16 |
| 6 | `Data3` | 2 | 小端 u16 |
| 8 | `Data4` | 8 | 原始字节序（按字节顺序输出） |

字符串形式：`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`（前 3 段大写 hex）

例：字节 `A6 6D 02 9B 3C 0D 5C 46 8B EE 51 99 D7 16 5C BA`
→ `9B026DA6-0D3C-465C-8BEE-5199D7165CBA`

---

## 7. SecurityDescriptor (ads_type=25)

参考 [MS-DTYP §2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)。

### 7.1 SD 头部 (20 字节)

| 偏移 | 字段 | 类型 | 说明 |
|---|---|---|---|
| 0 | `Revision` | `u8` | `1` |
| 1 | `Sbz1` | `u8` | `0` |
| 2 | `ControlFlags` | `u16` | 见 §7.2 |
| 4 | `OffsetOwner` | `u32` | Owner SID 相对 SD 起点的偏移；0 表示无 |
| 8 | `OffsetGroup` | `u32` | Group SID 偏移；0 表示无 |
| 12 | `OffsetSacl` | `u32` | SACL 偏移；0 表示无 |
| 16 | `OffsetDacl` | `u32` | DACL 偏移；0 表示无 |

> **读取方式**：所有 offset 都是相对 SD 字节流起点。读取时用切片 `&sd_bytes[offset..]`。

### 7.2 ControlFlags (u16 位掩码)

| 位 | 名称 | 含义 |
|---|---|---|
| 0x8000 | SR | Self Relative（self-contained buffer） |
| 0x4000 | RM | RM Control Valid |
| 0x2000 | PS | SACL Protected（不被继承） |
| 0x1000 | PD | DACL Protected |
| 0x0800 | SI | SACL Auto-Inherited |
| 0x0400 | DI | DACL Auto-Inherited |
| 0x0200 | SC | SACL Computed Inheritance Required |
| 0x0100 | DC | DACL Computed Inheritance Required |
| 0x0080 | SS | Server Security |
| 0x0040 | DT | DACL Trusted |
| 0x0020 | SD | SACL Defaulted |
| 0x0010 | SP | SACL Present |
| 0x0008 | DD | DACL Defaulted |
| 0x0004 | DP | DACL Present |
| 0x0002 | GD | Group Defaulted |
| 0x0001 | OD | Owner Defaulted |

`PS`/`PD` 位对 GUI 显示"该对象是否阻止继承"很有用。

### 7.3 ACL (8 字节头 + N 个 ACE)

| 偏移 | 字段 | 类型 |
|---|---|---|
| 0 | `AclRevision` | `u8` |
| 1 | `Sbz1` | `u8` |
| 2 | `AclSize` | `u16` | 本 ACL 总字节数（含头） |
| 4 | `AceCount` | `u16` | ACE 数量 |
| 6 | `Sbz2` | `u16` |

`AclRevision` 实测常见 `2` 或 `4`（4 = 包含 object ACE 的修订版）。

### 7.4 ACE

每个 ACE 都以 4 字节头开始，长度由 `AceSize` 决定：

| 偏移 | 字段 | 类型 |
|---|---|---|
| 0 | `AceType` | `u8` |
| 1 | `AceFlags` | `u8` |
| 2 | `AceSize` | `u16` |

下一个 ACE 起点 = 本 ACE 起点 + `AceSize`。

#### AceType 枚举

| 值 | 名称 | 后续数据布局 |
|---|---|---|
| 0x00 | ACCESS_ALLOWED | Mask + SID |
| 0x01 | ACCESS_DENIED | Mask + SID |
| 0x02 | SYSTEM_AUDIT | Mask + SID |
| 0x05 | ACCESS_ALLOWED_OBJECT | Mask + Flags + [ObjectType?] + [InheritedObjectType?] + SID |
| 0x06 | ACCESS_DENIED_OBJECT | 同上 |
| 0x07 | SYSTEM_AUDIT_OBJECT | 同上 + 额外字段 |
| 其他 | — | 一期可当 raw |

> **GUI 一期重点**：实际数据中绝大多数 ACE 是 `0x00` (ACCESS_ALLOWED) 和 `0x05` (ACCESS_ALLOWED_OBJECT)。优先实现这两种。

#### AceFlags 位掩码

| 位 | 名称 |
|---|---|
| 0x01 | OBJECT_INHERIT_ACE |
| 0x02 | CONTAINER_INHERIT_ACE |
| 0x04 | NO_PROPAGATE_INHERIT_ACE |
| 0x08 | INHERIT_ONLY_ACE |
| 0x10 | **INHERITED_ACE**（GUI 显示"是否继承"用此位） |
| 0x40 | SUCCESSFUL_ACCESS_ACE_FLAG |
| 0x80 | FAILED_ACCESS_ACE_FLAG |

### 7.5 ACE 数据区（类型 0x00 ACCESS_ALLOWED，最简）

```
[u32 Mask]
[SID]   // 委托方 (trustee)
```

### 7.6 ACE 数据区（类型 0x05 ACCESS_ALLOWED_OBJECT）

```
[u32 Mask]
[u32 Flags]                    // bit 0 = ACE_OBJECT_TYPE_PRESENT, bit 1 = ACE_INHERITED_OBJECT_TYPE_PRESENT
[GUID ObjectType]              // 仅当 Flags & 0x01, 16 字节
[GUID InheritedObjectType]     // 仅当 Flags & 0x02, 16 字节
[SID 委托方]
```

**ObjectType GUID 的语义**：决定这个权限是控制什么操作的（如改密码、写 SPN、复制 DC 数据等）。常见值见 §7.8。

### 7.7 AccessMask (u32 位掩码)

| 位 | 名称 | 含义 |
|---|---|---|
| 0x80000000 | GENERIC_READ | |
| 0x40000000 | GENERIC_WRITE | |
| 0x20000000 | GENERIC_EXECUTE | |
| 0x10000000 | GENERIC_ALL | 等价于完全控制 |
| 0x02000000 | MAXIMUM_ALLOWED | |
| 0x01000000 | ACCESS_SYSTEM_SECURITY | 访问 SACL |
| 0x00100000 | SYNCHRONIZE | |
| 0x00080000 | WRITE_OWNER | 取得所有权（攻防高价值） |
| 0x00040000 | WRITE_DACL | 改 DACL（攻防高价值） |
| 0x00020000 | READ_CONTROL | |
| 0x00010000 | DELETE | |
| 0x00000100 | ADS_RIGHT_DS_CONTROL_ACCESS | **扩展权限**（需查 ObjectType GUID，§7.8） |
| 0x00000020 | ADS_RIGHT_DS_WRITE_PROP | 写属性（ObjectType GUID 指明写哪个） |
| 0x00000010 | ADS_RIGHT_DS_READ_PROP | 读属性 |
| 0x00000008 | ADS_RIGHT_DS_SELF | Validated write |
| 0x00000002 | ADS_RIGHT_DS_DELETE_CHILD | |
| 0x00000001 | ADS_RIGHT_DS_CREATE_CHILD | |
| 0x0000FFFF | 对象特定权限（低 16 位） | |

> **GUI 解读优先级**：`GENERIC_ALL` / `WRITE_DACL` / `WRITE_OWNER` / `ADS_RIGHT_DS_CONTROL_ACCESS`(配合 §7.8) 是 BloodHound 攻击路径最关心的几种权限。

### 7.8 ACE ObjectType GUID → 权限名（攻防常用）

ObjectType GUID（当 Mask 含 `ADS_RIGHT_DS_CONTROL_ACCESS` 或 `ADS_RIGHT_DS_WRITE_PROP` 时）映射到具体权限。常用映射（来自 SharpHoundCommon 公开数据）：

| GUID | 权限名 | 攻防价值 |
|---|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DSReplicationGetChanges | DCSync |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DSReplicationGetChangesAll | DCSync |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DSReplicationGetChangesInFilteredSet | DCSync |
| `00299570-246d-11d0-a768-00aa006e0529` | UserForceChangePassword | 强制改密码 |
| `bf9679c0-0de6-11d0-a285-00aa003049e2` | WriteMember | 改组成员 |
| `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79` | WriteAllowedToAct | RBCD |
| `f3a64788-5306-11d1-a9c5-0000f80367c1` | WriteSPN | 改 SPN（Kerberoast） |
| `4c164200-20c0-11d0-a768-00aa006e0529` | UserAccountRestrictions | 改 UAC |
| `0e10c968-78fb-11d2-90d4-00c04f79dc55` | Enroll | 证书 enroll |
| `a05b8cc2-17bc-4802-a710-e7c15ab866a2` | AutoEnroll | 证书 auto-enroll |
| `00000000-0000-0000-0000-000000000000` | AllGuid | 所有属性（GenericWrite） |

> **GUI 表现建议**：ACE 列表展示 `(委托方 SID 解析后的对象名) → [权限名/类型] → [是否继承]`，DCSync / WriteSPN / WriteMember / ForceChangePassword 用醒目颜色标注。

---

## 8. Classes 段 (Properties 之后)

紧随 Properties 段（无显式长度，按 file pointer 顺序读）。描述 schema 类层级。**一期 GUI 可暂不解析**（Object 类型判断用 `objectClass` 属性即可）。

布局：`u32 numClasses` 后跟 `numClasses` 个 Class 结构（含 className、DN、subClassOf、schemaIDGUID、若干变长子结构）。详见 Python `structure.py` 的 `Class` 定义。

---

## 9. Rights 段 (Classes 之后)

紧随 Classes。描述扩展权限。`u32 numRights` 后跟 Right 结构（name、desc、20 字节 blob）。**一期 GUI 可暂不解析**（扩展权限名直接用 §7.8 的硬编码表）。

---

## 10. Treeview 段 (offset = treeviewOffset, 可缺失)

描述 AD 容器树（OU/Container 的父子关系）。**这个段在部分快照中可能不存在**——Python 版有 `adexpsnapshot/enrich.py` 专门用于重建缺失的 treeview 元数据。

> **一期 GUI 处理策略**：不解析 Treeview。OU/Container 的层级关系改用 `distinguishedName` 的字符串前缀匹配（DN 的逗号层级即 AD 容器层级）。这是 `adexplorersnapshot-rs` 的 `cache.rs:get_ou_children` 的做法，简单且对绝大多数场景够用。

---

## 11. 关键解析步骤顺序

为保证 file pointer 一致性，建议按以下顺序解析：

1. 读 Header（0x000 - 0x43E），拿到 `numObjects`、`metadataOffset`、`treeviewOffset`
2. seek 到 `metadataOffset`，读 `numProperties`，顺序解析所有 Property → `Vec<Property>`
3. seek 到 `0x43E`，循环 `numObjects` 次解析 Object（传入 `&[Property]` 用于按 `attrIndex` 查 ads_type）
4. seek 回 Properties 段末尾，顺序解析 Classes、Rights（如需要）
5. 构建 caches：遍历所有 Object 建 `HashMap<SID, obj_idx>` 和 `HashMap<dn_upper, obj_idx>`，用于把 ACE 委托方 SID 反查到具体对象
6. 遍历所有 Object 的 `nTSecurityDescriptor`，对每条 ACE 生成"委托方 → 目标对象"边

> **关于内存映射**：大快照（4GB+）建议用 `memmap2::Mmap` 映射整文件后用 `Cursor` seek，避免反复 `pread`。注意 `Object::parse` 里反复 seek 读取属性值在大快照上会产生大量 syscall，可优化为批量读取后再分派。

---

## 12. 一期实现的最小可行子集

针对 LdapHound GUI（表格 + 内嵌小图）展示 ACL 关联的目标，**最小可行实现只需**：

✅ 必须：Header、Object、Property、Attribute (ads_type 1/3/7/8/10/25)、SID、GUID、SecurityDescriptor、ACL、ACE (0x00/0x05)、AccessMask 解码、ObjectType GUID 表、SID/DN cache、边生成

🟡 二期：WellKnown SIDS 解析（`S-1-5-32-544` → `BUILTIN\Administrators`）、扩展权限完整表、Container 继承层级、LAPS 属性、证书模板

🔴 可跳过：Classes 段、Rights 段、Treeview 段、Trust、GPO、CertTemplate/CA、SACL

完成"必须"部分即可在 GUI 中显示：选中任一对象 → 列出其 nTSecurityDescriptor 中所有 ACE（委托方→权限→是否继承），并将委托方 SID 解析回对象名（用户/组/计算机）。

---

## 13. 参考资源

- **格式权威源**：`example/ADExplorerSnapshot/adexpsnapshot/parser/structure.py` (MIT, c3c)
- **语义参考**：`example/ADExplorerSnapshot/adexpsnapshot/parser/classes.py` 的 `processAttribute` 方法
- **MS-DTYP** (Security Descriptor / SID / ACL)：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
- **MS-ADTS** (AD 属性语义)：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- **ACE ObjectType GUID 表**：https://learn.microsoft.com/en-us/windows/win32/adschema/rights
- **BloodHound 数据模型参考**（输出 JSON schema）：https://github.com/SpecterOps/BloodHound/tree/master/src/test/fixtures

## 14. 实测校准数据（0718.dat）

| 检查项 | 期望值 | 用于单元测试 |
|---|---|---|
| `winAdSig` | `win-ad-ob\x00` | Header 校验 |
| `numObjects` | 3624 | Object 段循环次数 |
| `numProperties` (metadataOffset 处) | 1499 | Property 段循环次数 |
| `metadataOffset` | 2631269 (0x282665) | Properties 起点 |
| `treeviewOffset` | 3382092 (0x339B4C) | Treeview 起点 |
| `server` | `DC01.garfield.htb` | Header 解析 |
| Property[0].propName | `accountExpires` | Property 解析 |
| Property[0].adsType | `10` (LARGE_INTEGER) | ads_type 分派 |
| Property[1153].propName | `nTSecurityDescriptor` | 属性查找 |
| Property[1153].adsType | `25` | NTSD 解析触发 |
| 第一个 Object.objSize | 3076 | Object 边界推进 |
| 第一个 Object.tableSize | 23 | mapping 表长度 |
| 3624 对象解析后终点 | 0x28265D (距 metadataOffset 8 字节) | 整体布局校验 |
