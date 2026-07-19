//! Access mask bit decoding. Spec §7.7.

/// A 32-bit access mask. Implements bit-flag queries for the rights most
/// relevant to BloodHound-style attack-path analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(pub u32);

impl AccessMask {
    // Generic rights (high bits)
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;

    // Standard rights
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const WRITE_DACL: u32 = 0x0004_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const DELETE: u32 = 0x0001_0000;

    // AD-specific rights (low bits)
    pub const DS_CONTROL_ACCESS: u32 = 0x0000_0100;
    pub const DS_CREATE_CHILD: u32 = 0x0000_0001;
    pub const DS_DELETE_CHILD: u32 = 0x0000_0002;
    pub const DS_READ_PROP: u32 = 0x0000_0010;
    pub const DS_WRITE_PROP: u32 = 0x0000_0020;
    pub const DS_SELF: u32 = 0x0000_0008;

    pub fn raw(&self) -> u32 {
        self.0
    }

    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag == flag
    }

    pub fn is_generic_all(&self) -> bool {
        self.has(Self::GENERIC_ALL)
    }
    pub fn is_write_dacl(&self) -> bool {
        self.has(Self::WRITE_DACL)
    }
    pub fn is_write_owner(&self) -> bool {
        self.has(Self::WRITE_OWNER)
    }
    pub fn is_delete(&self) -> bool {
        self.has(Self::DELETE)
    }
    /// Extended right (controlled access) — requires consulting the ACE's
    /// ObjectType GUID (spec §7.8) to know *which* extended right.
    pub fn is_extended(&self) -> bool {
        self.has(Self::DS_CONTROL_ACCESS)
    }
    pub fn is_write_property(&self) -> bool {
        self.has(Self::DS_WRITE_PROP)
    }

    /// Human-readable set of standard/generic rights, for display.
    /// Does NOT decode extended rights — use the ACE's ObjectType GUID for
    /// those (see `crate::security::object_type_guid`).
    pub fn human_names(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.is_generic_all() {
            out.push("GenericAll");
        }
        if self.is_generic_read() {
            out.push("GenericRead");
        }
        if self.is_generic_write() {
            out.push("GenericWrite");
        }
        if self.is_generic_execute() {
            out.push("GenericExecute");
        }
        if self.is_write_dacl() {
            out.push("WriteDACL");
        }
        if self.is_write_owner() {
            out.push("WriteOwner");
        }
        if self.is_delete() {
            out.push("Delete");
        }
        if self.is_extended() {
            out.push("ExtendedRight");
        }
        if self.is_write_property() {
            out.push("WriteProperty");
        }
        if self.has(Self::DS_READ_PROP) {
            out.push("ReadProperty");
        }
        if self.has(Self::DS_SELF) {
            out.push("ValidatedWrite");
        }
        if self.has(Self::DS_CREATE_CHILD) {
            out.push("CreateChild");
        }
        if self.has(Self::DS_DELETE_CHILD) {
            out.push("DeleteChild");
        }
        out
    }

    fn is_generic_read(&self) -> bool {
        self.has(Self::GENERIC_READ)
    }
    fn is_generic_write(&self) -> bool {
        self.has(Self::GENERIC_WRITE)
    }
    fn is_generic_execute(&self) -> bool {
        self.has(Self::GENERIC_EXECUTE)
    }
}

impl std::fmt::Display for AccessMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}
