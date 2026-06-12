// SPDX-License-Identifier: MPL-2.0

//! Device-mapper device registry.

use alloc::collections::BTreeSet;
use core::sync::atomic::{AtomicU32, Ordering};

use aster_block::Error as BlockError;
use device_id::{DeviceId, MajorId, MinorId};
use ostd::sync::Mutex;
use spin::Once;

pub static DM_REGISTRY: Once<DmDeviceRegistry> = Once::new();

const DM_MAJOR_ID: u16 = 253;

pub struct DmDeviceRegistry {
    major: aster_block::MajorIdOwner,
    allocated_minors: Mutex<BTreeSet<u32>>,
    next_minor: AtomicU32,
}

impl DmDeviceRegistry {
    fn new(major: aster_block::MajorIdOwner) -> Self {
        Self {
            major,
            allocated_minors: Mutex::new(BTreeSet::new()),
            next_minor: AtomicU32::new(0),
        }
    }

    pub fn get() -> &'static DmDeviceRegistry {
        DM_REGISTRY.get().expect("dm registry must be initialized")
    }

    pub fn reserve_minor(&self, preferred_minor: Option<u32>) -> Result<u32, DmRegistryError> {
        let mut minors = self.allocated_minors.lock();

        if let Some(minor) = preferred_minor {
            if minors.insert(minor) {
                self.next_minor
                    .fetch_max(minor.saturating_add(1), Ordering::Relaxed);
                return Ok(minor);
            }

            return Err(DmRegistryError::MinorAlreadyAllocated(minor));
        }

        loop {
            let minor = self.next_minor.fetch_add(1, Ordering::Relaxed);
            if minors.insert(minor) {
                return Ok(minor);
            }
        }
    }

    pub fn release_minor(&self, minor: u32) {
        self.allocated_minors.lock().remove(&minor);
    }

    pub fn build_device_id(&self, minor: u32) -> DeviceId {
        DeviceId::new(self.major.get(), MinorId::new(minor))
    }
}

pub fn init() -> Result<(), BlockError> {
    if DM_REGISTRY.get().is_some() {
        return Ok(());
    }

    let major = aster_block::acquire_major(MajorId::new(DM_MAJOR_ID))?;
    DM_REGISTRY.call_once(|| DmDeviceRegistry::new(major));
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmRegistryError {
    MinorAlreadyAllocated(u32),
}
