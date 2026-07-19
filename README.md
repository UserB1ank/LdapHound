# LdapHound

**English** | [简体中文](./README.zh-CN.md)

> Deep-dive parser for Active Directory **Security Descriptors** — read
> ADExplorer `.dat` snapshots offline, no domain controller required.
> Ships with both a GUI and a CLI.

![1](docs\1.png)

## What it does

LdapHound reads the binary `.dat` snapshots exported by Sysinternals
ADExplorer and reconstructs each object's **nTSecurityDescriptor** in full
detail: owner/group SIDs, control flags, DACL/SACL, and every ACE. The
Security Descriptor is the core of AD access control — LdapHound turns the
raw self-relative binary blob into a human-readable, auditable structure.

- Decodes every common ACE type: `ACCESS_ALLOWED`, `ACCESS_DENIED`,
  `ACCESS_ALLOWED_OBJECT`, `ACCESS_DENIED_OBJECT`, plus the raw
  `SYSTEM_AUDIT` family
- Unpacks the AccessMask bitfield (GenericAll / WriteDACL / WriteOwner /
  ExtendedRight / WriteProperty / ...) and maps extended-right GUIDs to
  names — DCSync, WriteMember, WriteSPN, UserForceChangePassword,
  WriteAllowedToAct (RBCD), Enroll, etc.
- Resolves ACE trustee SIDs back to the snapshot object's
  `sAMAccountName` / display name so permissions read as
  "Administrators [group]" rather than a bare SID
- Surfaces inherited-vs-explicit and DACL-protected flags at a glance

Beyond SD parsing, LdapHound also reconstructs the directory tree
(Domain / Configuration / Schema naming contexts), decodes the common
`ads_type` attributes (String / Integer / OctetString / SID / GUID /
UTCTime), and supports RFC 4515 LDAP search filters
(`(&(objectCategory=Person)(objectClass=User))`, `(sAMAccountName=j*)`).

## Usage — GUI

```bash
cargo run --release -p ldaphound-gui
```

- Top menu bar: **Open .dat**
- Left sidebar: recursive tree over the three naming contexts, with
  expand/collapse, substring filter, per-type icons
- Main pane: object TitleBar (icon + name + class + DN), then two tabs
  - **Attributes** — sorted name|value list
  - **ACL** — each ACE rendered as its own card
    (#/Kind/Right/Mask/Inherited/Trustee). Long values scroll horizontally;
    in-card fields are drag-selectable + Ctrl+C-able. Selecting a card
    surfaces a Copy button for the whole row.
- Draggable divider between sidebar and main pane

## Usage — CLI

```bash
# List every object (ldapsearch-style output)
ldaphound-cli snapshot.dat

# Inspect one object's full Security Descriptor + ACL breakdown
ldaphound-cli snapshot.dat --object "CN=Administrator,CN=Users,DC=x"
ldaphound-cli snapshot.dat --object S-1-5-21-...-519

# Filter by coarse type (repeatable, OR-combined)
ldaphound-cli snapshot.dat --type user --type computer

# LDAP filter (AND-combined with --type)
ldaphound-cli snapshot.dat --filter '(&(objectCategory=Person)(objectClass=User))'
ldaphound-cli snapshot.dat --filter '(sAMAccountName=j*)'
```

Output is ldapsearch-style (`dn:` + `attribute: value`), pipe-friendly.

## Build & test

Requires Rust 1.85+ (edition 2024).

```bash
cargo build --release
cargo test  -p ldaphound-core --lib
```

## Background

The ADExplorer `.dat` format is undocumented and proprietary. Format
knowledge derives from the reverse engineering in
[`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py)
(MIT, by c3c), cross-referenced with
[MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/).
The parser is a clean-room implementation and does not incorporate code
from either source. Full format spec with field-offset tables and
calibration data: [`docs/snapshot-format.md`](./docs/snapshot-format.md).

## License

MIT. The bundled Bootstrap Icons font retains its own MIT license.
