// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::{
        file_table::{get_file_fast, FileDesc},
        utils::{FlockItem, FlockType},
    },
    prelude::*,
};

pub fn sys_flock(fd: FileDesc, ops: i32, ctx: &Context) -> Result<SyscallReturn> {
    debug!("flock: fd: {}, ops: {:?}", fd, ops);

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, fd);
    let inode_file = file.as_inode_or_err()?;
    let ops: FlockOps = FlockOps::from_i32(ops)?;
    if ops.contains(FlockOps::LOCK_UN) {
        inode_file.unlock_flock();
    } else {
        let is_nonblocking = ops.contains(FlockOps::LOCK_NB);
        let flock = {
            let type_ = FlockType::from(ops);
            FlockItem::new(&file, type_)
        };
        inode_file
            .set_flock(flock, is_nonblocking)
            .map_err(|err| match err.error() {
                Errno::EINTR => Error::new(Errno::ERESTARTSYS),
                _ => err,
            })?;
    }
    Ok(SyscallReturn::Return(0))
}

impl From<FlockOps> for FlockType {
    fn from(ops: FlockOps) -> Self {
        if ops.contains(FlockOps::LOCK_EX) {
            Self::ExclusiveLock
        } else if ops.contains(FlockOps::LOCK_SH) {
            Self::SharedLock
        } else {
            panic!("invalid flockops");
        }
    }
}

bitflags! {
    struct FlockOps: i32 {
        /// Shared lock
        const LOCK_SH = 1;
        /// Exclusive lock
        const LOCK_EX = 2;
        // Or'd with one of the above to prevent blocking
        const LOCK_NB = 4;
        // Remove lock
        const LOCK_UN = 8;
    }
}

impl FlockOps {
    fn from_i32(bits: i32) -> Result<Self> {
        if let Some(ops) = Self::from_bits(bits) {
            if ops.contains(Self::LOCK_SH) {
                if ops.contains(Self::LOCK_EX) || ops.contains(Self::LOCK_UN) {
                    return_errno_with_message!(Errno::EINVAL, "invalid operation");
                }
            } else if ops.contains(Self::LOCK_EX) {
                if ops.contains(Self::LOCK_UN) {
                    return_errno_with_message!(Errno::EINVAL, "invalid operation");
                }
            } else if !ops.contains(Self::LOCK_UN) {
                return_errno_with_message!(Errno::EINVAL, "invalid operation");
            }
            Ok(ops)
        } else {
            return_errno_with_message!(Errno::EINVAL, "invalid operation");
        }
    }
}
