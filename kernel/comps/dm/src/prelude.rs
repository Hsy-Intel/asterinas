// SPDX-License-Identifier: MPL-2.0

//! Prelude for the dm component.

pub use super::{
    device::DmDevice,
    registry::{DM_REGISTRY, DmDeviceRegistry},
    table::{DmDeviceFlags, DmTable, DmTableEntry, DmTargetParams},
    target::{DmTarget, DmTargetError},
};
