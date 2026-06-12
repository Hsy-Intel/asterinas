// SPDX-License-Identifier: MPL-2.0

//! Device-mapper table and table entry types.

use alloc::{string::String, vec::Vec};
use core::ops::Range;

/// A single entry in a device-mapper mapping table.
#[derive(Debug, Clone)]
pub struct DmTableEntry {
    pub logical_start: u64,
    pub length: u64,
    pub target_name: String,
    pub params: DmTargetParams,
}

impl DmTableEntry {
    pub fn sector_range(&self) -> Range<u64> {
        self.logical_start..self.logical_start + self.length
    }

    pub fn contains_sector(&self, sector: u64) -> bool {
        self.sector_range().contains(&sector)
    }

    pub fn logical_end(&self) -> u64 {
        self.logical_start + self.length
    }
}

/// Target-specific parameters for a device-mapper table entry.
#[derive(Debug, Clone)]
pub enum DmTargetParams {
    Linear {
        device_path: String,
        physical_start: u64,
    },
    Verity {
        version: u32,
        data_dev: String,
        hash_dev: String,
        data_block_size: u32,
        hash_block_size: u32,
        num_data_blocks: u32,
        hash_start_block: u32,
        hash_algorithm: String,
        root_hash: String,
        salt: String,
    },
}

/// A device-mapper mapping table.
#[derive(Debug, Clone)]
pub struct DmTable {
    pub name: String,
    pub flags: DmDeviceFlags,
    pub entries: Vec<DmTableEntry>,
}

impl DmTable {
    pub fn validate(&self) -> Result<(), DmTableError> {
        if self.entries.is_empty() {
            return Err(DmTableError::Empty);
        }

        let mut expected_start = 0;
        for entry in &self.entries {
            if entry.length == 0 {
                return Err(DmTableError::ZeroLength);
            }
            if entry.logical_start != expected_start {
                return Err(DmTableError::NonContiguous);
            }
            expected_start = entry.logical_end();
        }

        Ok(())
    }

    pub fn lookup_target(&self, sector: u64) -> Option<&DmTableEntry> {
        self.entries
            .iter()
            .find(|entry| entry.contains_sector(sector))
    }

    pub fn lookup_range(&self, start_sector: u64, end_sector: u64) -> Option<&DmTableEntry> {
        let last_sector = end_sector.checked_sub(1).unwrap_or(start_sector);
        let entry = self.lookup_target(start_sector)?;
        entry.contains_sector(last_sector).then_some(entry)
    }

    pub fn nr_sectors(&self) -> u64 {
        self.entries
            .last()
            .map(DmTableEntry::logical_end)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmTableError {
    Empty,
    NonContiguous,
    ZeroLength,
}

/// Device flags for a dm device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmDeviceFlags {
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::{DmDeviceFlags, DmTable, DmTableEntry, DmTableError, DmTargetParams};

    #[test]
    fn validates_contiguous_table() {
        let table = DmTable {
            name: String::from("vm_verity"),
            flags: DmDeviceFlags { read_only: true },
            entries: vec![DmTableEntry {
                logical_start: 0,
                length: 128,
                target_name: String::from("linear"),
                params: DmTargetParams::Linear {
                    device_path: String::from("/dev/vda1"),
                    physical_start: 8,
                },
            }],
        };

        assert_eq!(table.validate(), Ok(()));
        assert_eq!(table.nr_sectors(), 128);
        assert!(table.lookup_range(0, 64).is_some());
    }

    #[test]
    fn rejects_non_contiguous_table() {
        let table = DmTable {
            name: String::from("broken"),
            flags: DmDeviceFlags::default(),
            entries: vec![DmTableEntry {
                logical_start: 4,
                length: 128,
                target_name: String::from("linear"),
                params: DmTargetParams::Linear {
                    device_path: String::from("/dev/vda1"),
                    physical_start: 8,
                },
            }],
        };

        assert_eq!(table.validate(), Err(DmTableError::NonContiguous));
    }
}
