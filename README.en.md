# LdapHound

**English** | [简体中文](./README.zh-CN.md)

> Offline inspector for ADExplorer `.dat` snapshots — parse, browse, and audit
> Active Directory ACL relationships without ever touching a domain controller.

## Overview

LdapHound parses the binary `.dat` snapshots exported by Sysinternals
ADExplorer directly, rebuilds the AD directory tree (Domain / Configuration /
Schema naming contexts), and exposes each object's attributes and ACL
(DACL/ACE). Everything runs locally — no domain controller connection is
required. Use cases:

- Auditing decommissioned AD snapshots after the fact
- AD data review during red-team exercises / CTFs
- Offline supplementation of BloodHound data
- Reverse-engineering research of the ADExplorer snapshot format

## Features

### Parser library (`ldaphound-core`)

- Full ADExplorer `.dat` format parse (Header / Properties / Objects / Classes)
- Decodes every common `ads_type`: String / Integer / LargeInteger /
  OctetString / Boolean / UTCTime / NT_SECURITY_DESCRIPTOR
- SID parsing (note: `IdentifierAuthority` is big-endian) and GUID
  (mixed-endian)
- Full SecurityDescriptor / ACL / ACE decode, covering
  `ACCESS_ALLOWED` / `ACCESS_DENIED` / `ACCESS_ALLOWED_OBJECT` /
  `ACCESS_DENIED_OBJECT` ACE types
- AccessMask bitmask decode + extended-right GUID mapping (auto-recognises
  high-value rights like DCSync / WriteMember / WriteSPN / RBCD)
- Directory tree construction: parent/child derived from DN, three NC
  roots auto-detected by class
- LDAP search filter (RFC 4515 subset): `(&...)`, `(|...)`, `(!...)`,
  `(attr=value)`, `(attr>=value)`, `(attr=pre*fix)`, `(attr=*)`
  - `objectCategory` friendly matching: DN form
    (`CN=Person,CN=Schema,...`) and bare CN (`Person`) are equivalent
- Memory-mapped + background-thread parsing keeps the UI responsive on
  4GB+ snapshots

### Command line (`ldaphound-cli`)

```bash
# List all objects (ldapsearch-style)
ldaphound-cli snapshot.dat

# Inspect a single object's ACL by index / DN / SID
ldaphound-cli snapshot.dat --object "CN=Administrator,CN=Users,DC=x"
ldaphound-cli snapshot.dat --object S-1-5-21-...-519

# Filter by coarse type (repeatable, OR-combined)
ldaphound-cli snapshot.dat --type user --type computer

# LDAP filter (AND-combined with --type)
ldaphound-cli snapshot.dat --filter '(&(objectCategory=Person)(objectClass=User))'
ldaphound-cli snapshot.dat --filter '(sAMAccountName=j*)'
```

Output is ldapsearch-style (`dn:` + `attribute: value`), pipe-friendly.

### GUI (`ldaphound-gui`)

Built on iced 0.14 + iced_aw, layout inspired by the halloy IRC client:

- **Top menu bar**: Open .dat button + status line
- **Left sidebar**: recursive tree over the three naming contexts with
  expand/collapse, substring filter on DN/name, and per-type icons
  (user, computer, container, ...)
- **Draggable divider**: pane_grid splitter between sidebar and main pane
- **Main pane TitleBar**: object icon + name + class + DN
- **Attributes / ACL tabs**:
  - Attributes: sorted alphabetically by name
  - ACL: each ACE rendered as its own card
    (#/Kind/Right/Mask/Inherited/Trustee); long values scroll horizontally,
    in-card fields are drag-selectable + Ctrl+C-able
- **ACL trustee resolution**: SIDs are reverse-looked-up to the object's
  `sAMAccountName` (or principal/display name)
- Bundled Bootstrap Icons font, dark theme

## Project layout

```
LdapHound/
├── crates/
│   ├── ldaphound-core/        # parser library (no GUI deps, independently testable)
│   │   └── src/
│   │       ├── snapshot/      # dat parsing (Header/Property/Object/Attribute)
│   │       ├── security/      # SD/ACL/ACE/AccessMask/ObjectTypeGUID
│   │       ├── filter.rs      # LDAP search filter parse + evaluation
│   │       ├── tree.rs        # directory tree construction
│   │       ├── dump.rs        # ldapsearch-style output
│   │       ├── sid.rs / guid.rs
│   │       └── bin/cli.rs     # CLI entry
│   └── ldaphound-gui/         # iced GUI
│       └── src/
│           ├── app.rs         # state + Elm update/view
│           ├── view/          # sidebar + object_view
│           ├── theme.rs       # palette + button/container styles
│           └── icon.rs        # Bootstrap Icons glyphs
├── docs/
│   └── snapshot-format.md     # .dat format spec (calibrated against real data)
└── Cargo.toml                 # workspace
```

## Building

Requires Rust 1.85+ (edition 2024).

```bash
# Build everything
cargo build --release

# Run the GUI
cargo run --release -p ldaphound-gui

# Run the CLI
cargo run --release -p ldaphound-core --bin ldaphound-cli -- snapshot.dat
```

## Tests

```bash
cargo test -p ldaphound-core --lib
```

Coverage: SID/GUID byte parsing, Header field offsets, LDAP filter parse +
evaluation (including `objectCategory` DN-vs-CN matching), directory tree
construction.

## Background

The ADExplorer `.dat` format is a Microsoft proprietary binary format with
no official documentation. The format knowledge in this project derives
from the reverse engineering done by
[`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py)
(MIT licensed, by c3c), cross-referenced with the public
[MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/)
specification. The parser is a clean-room implementation that does not
incorporate code from either source.

For the full format specification with field-offset tables and calibration
data verified against real snapshots, see
[`docs/snapshot-format.md`](./docs/snapshot-format.md).

## License

MIT. See [LICENSE](./LICENSE).

The Bootstrap Icons font (`assets/bootstrap-icons.ttf`) is used under its
own MIT license.
