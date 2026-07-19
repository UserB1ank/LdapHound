//! Map ACE ObjectType GUIDs to human-readable right names. Spec §7.8.
//!
//! Source: SharpHoundCommon's `ACEGuids.cs` (public AD rights reference).
//! GUIDs are matched case-insensitively in canonical uppercase form.

use crate::guid::Guid;

/// A named extended right / validated write / property set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedRight {
    pub guid: &'static str,
    pub name: &'static str,
    /// Whether this right is widely considered high-value for attackers
    /// (DCSync, force-change-password, RBCD, etc.). GUI may highlight these.
    pub high_value: bool,
}

/// Lookup a right by its GUID string (canonical uppercase).
pub fn lookup(guid_str: &str) -> Option<&'static NamedRight> {
    TABLE.iter().find(|r| r.guid.eq_ignore_ascii_case(guid_str))
}

/// Lookup by [`Guid`] value.
pub fn lookup_guid(g: &Guid) -> Option<&'static NamedRight> {
    let s = g.to_string();
    lookup(&s)
}

/// All known extended/property rights. Keep sorted by name for grep-ability.
pub static TABLE: &[NamedRight] = &[
    NamedRight {
        guid: "1131F6AA-9C07-11D1-F79F-00C04FC2DCD2",
        name: "DS-Replication-Get-Changes",
        high_value: true,
    },
    NamedRight {
        guid: "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2",
        name: "DS-Replication-Get-Changes-All",
        high_value: true,
    },
    NamedRight {
        guid: "89E95B76-444D-4C62-991A-0FACBEDA640C",
        name: "DS-Replication-Get-Changes-In-Filtered-Set",
        high_value: true,
    },
    NamedRight {
        guid: "00299570-246D-11D0-A768-00AA006E0529",
        name: "User-Force-Change-Password",
        high_value: true,
    },
    NamedRight {
        guid: "BF9679C0-0DE6-11D0-A285-00AA003049E2",
        name: "Write-Member",
        high_value: true,
    },
    NamedRight {
        guid: "3F78C3E5-F79A-46BD-A0B8-9D18116DDC79",
        name: "Write-Allowed-To-Act",
        high_value: true,
    },
    NamedRight {
        guid: "F3A64788-5306-11D1-A9C5-0000F80367C1",
        name: "Write-SPN",
        high_value: true,
    },
    NamedRight {
        guid: "5B47D60F-6090-40B2-9F37-2A4DE88F3063",
        name: "Add-Key-Principal",
        high_value: true,
    },
    NamedRight {
        guid: "4C164200-20C0-11D0-A768-00AA006E0529",
        name: "User-Account-Restrictions",
        high_value: true,
    },
    NamedRight {
        guid: "EA1DDDC4-60FF-416E-8CC0-17CEE534BCE7",
        name: "PKI-Certificate-Name-Flag",
        high_value: false,
    },
    NamedRight {
        guid: "D15EF7D8-F226-46DB-AE79-B34E560BD12C",
        name: "PKI-Enrollment-Flag",
        high_value: false,
    },
    NamedRight {
        guid: "0E10C968-78FB-11D2-90D4-00C04F79DC55",
        name: "Enroll",
        high_value: false,
    },
    NamedRight {
        guid: "A05B8CC2-17BC-4802-A710-E7C15AB866A2",
        name: "AutoEnroll",
        high_value: false,
    },
    NamedRight {
        guid: "00000000-0000-0000-0000-000000000000",
        name: "All",
        high_value: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_dcsync_guid() {
        let r = lookup("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2").unwrap();
        assert_eq!(r.name, "DS-Replication-Get-Changes-All");
        assert!(r.high_value);
    }

    #[test]
    fn case_insensitive_match() {
        assert!(lookup("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2").is_some());
    }

    #[test]
    fn unknown_guid_returns_none() {
        assert!(lookup("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF").is_none());
    }
}
