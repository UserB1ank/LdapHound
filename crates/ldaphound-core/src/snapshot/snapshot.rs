//! Top-level snapshot parser. Spec §0, §11.
//!
//! Parsing order is order-dependent on the file pointer:
//! 1. Header (0x000 - 0x43E)
//! 2. Properties (at metadataOffset) — must be parsed before objects because
//!    objects reference properties by index.
//! 3. Objects (at 0x43E, numObjects of them).
//! Classes/Rights/Treeview are skipped in v1 (see spec §8/§9/§10).

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;
use crate::le_reader::LeReader;
use crate::snapshot::header::{Header, OBJECTS_START};
use crate::snapshot::object::Object;
use crate::snapshot::property::Property;

/// A fully-parsed snapshot. Owned data, `Send + Sync` — safe to move across
/// threads (required by the GUI's async task layer).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub header: Header,
    /// Properties in segment order; objects reference these by index.
    pub properties: Vec<Property>,
    /// Lowercased property name → index in `properties`.
    pub property_index: HashMap<String, usize>,
    /// Objects in segment order.
    pub objects: Vec<Object>,
}

impl Snapshot {
    /// Parse from a `.dat` file. The file is memory-mapped; parsed data is
    /// copied into owned `Vec`s so the returned `Snapshot` does not borrow
    /// the mmap and can be sent across threads freely.
    pub fn parse_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        // SAFETY: mmap of a file we just opened read-only. We do not mutate
        // the underlying file while the mapping is live (LdapHound is a
        // read-only viewer). If the file is modified externally during
        // parsing, behaviour is undefined — acceptable for a local tool.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Self::parse_bytes(&mmap)
    }

    /// Parse from an in-memory byte slice. Used by tests and the GUI's
    /// background task (which already mmap'd the file).
    pub fn parse_bytes(data: &[u8]) -> Result<Self> {
        let mut r = LeReader::new(data);

        // 1. Header.
        let header = Header::parse(&mut r)?;

        // 2. Properties (at metadataOffset).
        r.seek(header.metadata_offset)?;
        let num_properties = r.read_u32()? as usize;
        let mut properties = Vec::with_capacity(num_properties);
        let mut property_index = HashMap::with_capacity(num_properties);
        for i in 0..num_properties {
            let p = Property::parse(&mut r)?;
            property_index.insert(p.name.to_ascii_lowercase(), i);
            properties.push(p);
        }

        // 3. Objects (at 0x43E).
        r.seek(OBJECTS_START)?;
        let mut objects = Vec::with_capacity(header.num_objects as usize);
        for _ in 0..header.num_objects {
            let obj_start = r.pos();
            objects.push(Object::parse(&mut r, obj_start, &properties)?);
        }

        Ok(Self {
            header,
            properties,
            property_index,
            objects,
        })
    }

    /// Look up a property by (case-insensitive) name.
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.property_index
            .get(&name.to_ascii_lowercase())
            .and_then(|&i| self.properties.get(i))
    }

    /// Index of a property by name, if present.
    pub fn property_index_of(&self, name: &str) -> Option<usize> {
        self.property_index
            .get(&name.to_ascii_lowercase())
            .copied()
    }
}
