// SPDX-License-Identifier: MPL-2.0

//! Device-mapper framework for Asterinas.
#![no_std]
#![deny(unsafe_code)]
//!
//! This crate provides a minimal device-mapper framework that supports
//! creating virtual block devices from kernel command-line parameters.

extern crate alloc;

macro_rules! __log_prefix {
    () => {
        "dm: "
    };
}

pub mod cmdline;
mod device;
pub mod prelude;
mod registry;
mod table;
mod target;

pub use cmdline::DM_CREATE_ARGS;
use component::{ComponentInitError, init_component};
pub use device::DmDevice;
pub use registry::DM_REGISTRY;
pub use table::{DmDeviceFlags, DmTable, DmTableEntry, DmTargetParams};
pub use target::{DmTarget, DmTargetError, DmTargetResult};

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    registry::init().map_err(|_| ComponentInitError::Unknown)?;
    Ok(())
}

pub fn init_in_first_kthread() {
    cmdline::init();
}
