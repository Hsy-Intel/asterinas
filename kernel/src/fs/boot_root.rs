// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_block::BlockDevice;
use spin::Once;

use super::{
    ext2::Ext2,
    file::{InodeMode, InodeType},
    vfs::{
        file_system::FileSystem,
        path::{FsPath, Path, PathResolver, PerMountFlags},
    },
};
use crate::prelude::*;

const BOOT_ROOT_MOUNTPOINT: &str = "/.aster_root";
static ROOT_DEVICE: Once<String> = Once::new();
static ROOT_FS_TYPE: Once<String> = Once::new();
static ROOT_READ_ONLY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BOOT_ROOT: Once<BootRoot> = Once::new();

aster_cmdline::define_kv_param!("root", ROOT_DEVICE);
aster_cmdline::define_kv_param!("rootfstype", ROOT_FS_TYPE);
aster_cmdline::define_flag_param!("ro", ROOT_READ_ONLY);

struct BootRoot {
    device_path: String,
}

pub fn prepare_in_first_kthread(path_resolver: &PathResolver) {
    if BOOT_ROOT.get().is_some() {
        return;
    }

    let Some(root_device) = ROOT_DEVICE.get() else {
        return;
    };
    let Some(root_fs_type) = ROOT_FS_TYPE.get() else {
        warn!(
            "root device '{}' specified without rootfstype; keeping initramfs root",
            root_device
        );
        return;
    };

    if root_fs_type != "ext2" {
        warn!(
            "rootfstype='{}' is not supported for early verified-root bootstrap; keeping initramfs root",
            root_fs_type
        );
        return;
    }

    match prepare_boot_root_mount(path_resolver, root_device) {
        Ok(()) => {
            BOOT_ROOT.call_once(|| BootRoot {
                device_path: root_device.clone(),
            });
            println!(
                "[kernel] prepared verified root bootstrap from {} at {}{}",
                root_device,
                BOOT_ROOT_MOUNTPOINT,
                if ROOT_READ_ONLY.load(core::sync::atomic::Ordering::Relaxed) {
                    " (ro)"
                } else {
                    ""
                }
            );
        }
        Err(error) => {
            warn!(
                "failed to prepare verified root bootstrap from '{}': {:?}; keeping initramfs root",
                root_device, error
            );
        }
    }
}

fn prepare_boot_root_mount(path_resolver: &PathResolver, root_device: &str) -> Result<()> {
    let mountpoint = ensure_boot_root_mountpoint(path_resolver)?;
    let block_device = resolve_block_device(path_resolver, root_device)?;
    let fs = Ext2::open(block_device, None).map(|fs| fs as Arc<dyn FileSystem>)?;
    mountpoint.mount_for_bootstrap(fs, PerMountFlags::empty(), Some(root_device.to_string()))?;
    Ok(())
}

fn ensure_boot_root_mountpoint(path_resolver: &PathResolver) -> Result<Path> {
    let mountpoint_path = FsPath::try_from(BOOT_ROOT_MOUNTPOINT)?;
    if let Ok(path) = path_resolver.lookup(&mountpoint_path) {
        return Ok(path);
    }

    path_resolver.root().new_fs_child(
        BOOT_ROOT_MOUNTPOINT.trim_start_matches('/'),
        InodeType::Dir,
        InodeMode::from_bits_truncate(0o755),
    )
}

fn resolve_block_device(
    path_resolver: &PathResolver,
    root_device: &str,
) -> Result<Arc<dyn BlockDevice>> {
    let fs_path = FsPath::try_from(root_device)?;
    if let Ok(path) = path_resolver.lookup_no_follow(&fs_path) {
        if !path.type_().is_device() {
            return_errno_with_message!(Errno::ENODEV, "the root path is not a device file");
        }
        let device_id = path.metadata().self_dev_id.ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "the root device inode has no device id")
        })?;
        return aster_block::lookup(device_id).ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "the root block device is not registered")
        });
    }

    let Some(device_name) = root_device.rsplit('/').next() else {
        return_errno_with_message!(Errno::ENODEV, "the root device path is invalid");
    };

    aster_block::collect_all()
        .into_iter()
        .find(|device| device.name() == device_name)
        .ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "the root block device is not registered")
        })
}

pub fn resolve_init_path(path: &str) -> String {
    if !is_active() || path.starts_with(BOOT_ROOT_MOUNTPOINT) || !path.starts_with('/') {
        return path.to_string();
    }

    format!("{}{}", BOOT_ROOT_MOUNTPOINT, path)
}

pub fn activate_in_first_process(ctx: &Context) -> Result<()> {
    let Some(boot_root) = BOOT_ROOT.get() else {
        return Ok(());
    };

    let fs_ref = ctx.thread_local.borrow_fs();
    let mut resolver = fs_ref.resolver().write();
    let old_dev_path = resolver.lookup(&FsPath::try_from("/dev")?)?;
    let mountpoint_path = FsPath::try_from(BOOT_ROOT_MOUNTPOINT)?;
    let boot_root_path = resolver.lookup(&mountpoint_path)?;
    let new_dev_path = match resolver.lookup(&FsPath::try_from(
        format!("{}/dev", BOOT_ROOT_MOUNTPOINT).as_str(),
    )?) {
        Ok(path) => path,
        Err(_) => boot_root_path.new_fs_child(
            "dev",
            InodeType::Dir,
            InodeMode::from_bits_truncate(0o755),
        )?,
    };

    old_dev_path.bind_mount_to(&new_dev_path, true, ctx)?;
    resolver.set_root(boot_root_path.clone());
    resolver.set_cwd(boot_root_path);

    println!(
        "[kernel] switched init process root to verified device {}",
        boot_root.device_path
    );
    Ok(())
}

pub fn is_active() -> bool {
    BOOT_ROOT.get().is_some()
}
