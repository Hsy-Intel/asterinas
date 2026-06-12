// SPDX-License-Identifier: MPL-2.0

//! Kernel command-line support for the device-mapper framework.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use super::{
    device::DmDevice,
    registry::{DmDeviceRegistry, DmRegistryError},
    table::{DmDeviceFlags, DmTable, DmTableEntry, DmTableError, DmTargetParams},
    target::{DmTargetError, create_target},
};

/// Storage for parsed dm-mod.create arguments.
pub static DM_CREATE_ARGS: spin::Once<Vec<String>> = spin::Once::new();
aster_cmdline::define_repeatable_kv_param!("dm_mod.create", DM_CREATE_ARGS);

/// Initializes the dm component from kernel command-line parameters.
pub fn init() {
    let Some(args) = DM_CREATE_ARGS.get() else {
        return;
    };

    for arg in args {
        match create_dm_device(arg) {
            Ok((device, minor)) => {
                if let Err(error) = aster_block::register(device) {
                    DmDeviceRegistry::get().release_minor(minor);
                    ostd::warn!("failed to register dm device from '{}': {:?}", arg, error);
                }
            }
            Err(error) => {
                ostd::warn!("failed to create dm device from '{}': {:?}", arg, error);
            }
        }
    }
}

fn create_dm_device(arg: &str) -> Result<(Arc<dyn aster_block::BlockDevice>, u32), DmCreateError> {
    let request = parse_create_arg(arg.trim_matches('"'))?;
    let registry = DmDeviceRegistry::get();
    let minor = registry.reserve_minor(request.minor)?;
    let id = registry.build_device_id(minor);
    let target = match create_target(&request.table.entries[0], &request.table.flags) {
        Ok(target) => target,
        Err(error) => {
            registry.release_minor(minor);
            return Err(error.into());
        }
    };
    let device = DmDevice::new(id, minor, request.table, target);

    Ok((Arc::new(device) as Arc<dyn aster_block::BlockDevice>, minor))
}

fn parse_create_arg(arg: &str) -> Result<DmCreateRequest, DmCreateError> {
    let mut parts = arg.splitn(5, ',');

    let name = parts
        .next()
        .ok_or(DmCreateError::MissingField("device name"))?
        .trim();
    let uuid = parts.next().unwrap_or("").trim();
    let minor = parse_optional_minor(parts.next().unwrap_or(""))?;
    let flags = parse_flags(parts.next().unwrap_or(""))?;
    let table_str = parts
        .next()
        .ok_or(DmCreateError::MissingField("device table"))?
        .trim();

    if name.is_empty() {
        return Err(DmCreateError::InvalidField("device name"));
    }

    let table = DmTable {
        name: name.to_string(),
        flags,
        entries: vec![parse_table_entry(table_str)?],
    };
    table.validate().map_err(DmCreateError::from)?;

    Ok(DmCreateRequest {
        _uuid: (!uuid.is_empty()).then_some(uuid.to_string()),
        minor,
        table,
    })
}

/// Parses a single table entry line.
fn parse_table_entry(line: &str) -> Result<DmTableEntry, DmCreateError> {
    let mut tokens = line.split_whitespace();

    let logical_start = parse_u64(tokens.next(), "logical start sector")?;
    let length = parse_u64(tokens.next(), "logical sector count")?;
    let target_name = tokens
        .next()
        .ok_or(DmCreateError::MissingField("target name"))?;

    let params = match target_name {
        "linear" => parse_linear_params(&mut tokens)?,
        "verity" => parse_verity_params(&mut tokens)?,
        _ => return Err(DmCreateError::UnsupportedTarget),
    };

    if tokens.next().is_some() {
        return Err(DmCreateError::TrailingTokens);
    }

    Ok(DmTableEntry {
        logical_start,
        length,
        target_name: target_name.to_string(),
        params,
    })
}

fn parse_linear_params(
    tokens: &mut core::str::SplitWhitespace<'_>,
) -> Result<DmTargetParams, DmCreateError> {
    let device_path = tokens
        .next()
        .ok_or(DmCreateError::MissingField("linear device path"))?
        .to_string();
    let physical_start = parse_u64(tokens.next(), "linear physical start")?;

    Ok(DmTargetParams::Linear {
        device_path,
        physical_start,
    })
}

fn parse_verity_params(
    tokens: &mut core::str::SplitWhitespace<'_>,
) -> Result<DmTargetParams, DmCreateError> {
    let version = parse_u32(tokens.next(), "verity version")?;
    let data_dev = tokens
        .next()
        .ok_or(DmCreateError::MissingField("verity data device"))?
        .to_string();
    let hash_dev = tokens
        .next()
        .ok_or(DmCreateError::MissingField("verity hash device"))?
        .to_string();
    let data_block_size = parse_u32(tokens.next(), "verity data block size")?;
    let hash_block_size = parse_u32(tokens.next(), "verity hash block size")?;
    let num_data_blocks = parse_u32(tokens.next(), "verity data block count")?;
    let hash_start_block = parse_u32(tokens.next(), "verity hash start block")?;
    let hash_algorithm = tokens
        .next()
        .ok_or(DmCreateError::MissingField("verity hash algorithm"))?
        .to_string();
    let root_hash = parse_hex_string(tokens.next(), "verity root hash")?;
    let salt = parse_hex_string(tokens.next(), "verity salt")?;

    if data_block_size == 0 || hash_block_size == 0 || num_data_blocks == 0 {
        return Err(DmCreateError::InvalidField("verity geometry"));
    }

    Ok(DmTargetParams::Verity {
        version,
        data_dev,
        hash_dev,
        data_block_size,
        hash_block_size,
        num_data_blocks,
        hash_start_block,
        hash_algorithm,
        root_hash,
        salt,
    })
}

fn parse_flags(flags: &str) -> Result<DmDeviceFlags, DmCreateError> {
    if flags.trim().is_empty() {
        return Ok(DmDeviceFlags { read_only: false });
    }

    let mut read_only = false;
    for flag in flags.split(['|', ' ']) {
        if flag.is_empty() {
            continue;
        }

        match flag {
            "ro" => read_only = true,
            _ => return Err(DmCreateError::InvalidField("device flags")),
        }
    }

    Ok(DmDeviceFlags { read_only })
}

fn parse_optional_minor(value: &str) -> Result<Option<u32>, DmCreateError> {
    if value.trim().is_empty() {
        return Ok(None);
    }

    value
        .trim()
        .parse()
        .map(Some)
        .map_err(|_| DmCreateError::InvalidField("device minor"))
}

fn parse_u32(value: Option<&str>, field: &'static str) -> Result<u32, DmCreateError> {
    value
        .ok_or(DmCreateError::MissingField(field))?
        .parse()
        .map_err(|_| DmCreateError::InvalidField(field))
}

fn parse_u64(value: Option<&str>, field: &'static str) -> Result<u64, DmCreateError> {
    value
        .ok_or(DmCreateError::MissingField(field))?
        .parse()
        .map_err(|_| DmCreateError::InvalidField(field))
}

fn parse_hex_string(value: Option<&str>, field: &'static str) -> Result<String, DmCreateError> {
    let value = value.ok_or(DmCreateError::MissingField(field))?;
    if value.len() % 2 != 0 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DmCreateError::InvalidField(field));
    }

    Ok(value.to_string())
}

#[derive(Debug)]
struct DmCreateRequest {
    _uuid: Option<String>,
    minor: Option<u32>,
    table: DmTable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DmCreateError {
    MissingField(&'static str),
    InvalidField(&'static str),
    TrailingTokens,
    UnsupportedTarget,
    Table(DmTableError),
    Target(DmTargetError),
    Registry(DmRegistryError),
}

impl From<DmTableError> for DmCreateError {
    fn from(error: DmTableError) -> Self {
        Self::Table(error)
    }
}

impl From<DmTargetError> for DmCreateError {
    fn from(error: DmTargetError) -> Self {
        Self::Target(error)
    }
}

impl From<DmRegistryError> for DmCreateError {
    fn from(error: DmRegistryError) -> Self {
        Self::Registry(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{DmCreateError, parse_create_arg};
    use crate::table::DmTableError;

    #[test]
    fn parses_linear_create_argument() {
        let request = parse_create_arg("vm_linear,,7,ro,0 128 linear /dev/vda1 8").unwrap();

        assert_eq!(request.table.name, "vm_linear");
        assert_eq!(request.minor, Some(7));
        assert!(request.table.flags.read_only);
        assert_eq!(request.table.entries.len(), 1);
        assert_eq!(request.table.entries[0].target_name, "linear");
    }

    #[test]
    fn parses_verity_create_argument() {
        let request = parse_create_arg(
            "vm_verity,,,ro,0 512000 verity 1 /dev/vda1 /dev/vda2 4096 4096 64000 0 sha256 0123456789abcdef 00",
        )
        .unwrap();

        assert_eq!(request.table.entries[0].target_name, "verity");
    }

    #[test]
    fn rejects_invalid_hex_root_hash() {
        let error = parse_create_arg(
            "vm_verity,,,ro,0 512000 verity 1 /dev/vda1 /dev/vda2 4096 4096 64000 0 sha256 xyz 00",
        )
        .unwrap_err();

        assert_eq!(error, DmCreateError::InvalidField("verity root hash"));
    }

    #[test]
    fn rejects_non_zero_first_logical_sector() {
        let error = parse_create_arg("vm_linear,,,ro,4 128 linear /dev/vda1 8").unwrap_err();

        assert_eq!(error, DmCreateError::Table(DmTableError::NonContiguous));
    }
}
