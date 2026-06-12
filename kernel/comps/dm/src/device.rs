// SPDX-License-Identifier: MPL-2.0

//! Device-mapper virtual block device.

use alloc::{format, string::String, sync::Arc};

use aster_block::{
    BlockDevice, BlockDeviceMeta,
    bio::{BioEnqueueError, BioType, SubmittedBio},
};
use device_id::DeviceId;

use super::{table::DmTable, target::DmTarget};

/// A device-mapper virtual block device.
#[derive(Debug)]
pub struct DmDevice {
    id: DeviceId,
    name: String,
    table: DmTable,
    target: Arc<dyn DmTarget>,
}

impl DmDevice {
    /// Creates a new dm device from a validated table and instantiated target.
    pub fn new(id: DeviceId, minor: u32, table: DmTable, target: Arc<dyn DmTarget>) -> Self {
        Self {
            id,
            name: format!("dm-{minor}"),
            table,
            target,
        }
    }

    /// Returns the mapping table for this device.
    pub fn table(&self) -> &DmTable {
        &self.table
    }

    /// Returns the configured logical name for this device.
    pub fn logical_name(&self) -> &str {
        &self.table.name
    }

    /// Returns the underlying target.
    pub fn target(&self) -> &Arc<dyn DmTarget> {
        &self.target
    }
}

impl BlockDevice for DmDevice {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        if self.table.flags.read_only && bio.type_() == BioType::Write {
            return Err(BioEnqueueError::Refused);
        }

        if bio.type_() != BioType::Flush {
            let start_sector = bio.sid_range().start.to_raw();
            let end_sector = bio.sid_range().end.to_raw();
            if self.table.lookup_range(start_sector, end_sector).is_none() {
                return Err(BioEnqueueError::Refused);
            }
        }

        self.target
            .map_bio(bio)
            .map_err(|_| BioEnqueueError::Refused)
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: self.target.max_nr_segments_per_bio(),
            nr_sectors: self.table.nr_sectors() as usize,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn is_partition(&self) -> bool {
        false
    }
}
