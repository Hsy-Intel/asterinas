// SPDX-License-Identifier: MPL-2.0

//! Device-mapper target trait and error types.

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::num::NonZeroUsize;

use aster_block::{
    BlockDevice, SECTOR_SIZE,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio},
};
use ostd::{
    Error,
    mm::{VmIo, io::util::HasVmReaderWriter},
    sync::{Mutex, RwLock},
};
use sha2::{Digest, Sha256};

use super::table::{DmDeviceFlags, DmTableEntry, DmTargetParams};

/// Errors that can occur during target operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmTargetError {
    /// The requested sector range is out of bounds.
    OutOfBounds,
    /// The target configuration is invalid.
    InvalidConfig,
    /// The target references a block device that does not exist.
    DeviceNotFound,
    /// The target is read-only and write operations are not permitted.
    ReadOnly,
    /// A cryptographic verification failed.
    VerificationFailed,
    /// An I/O error occurred in the underlying target implementation.
    IoError,
    /// The target is not ready or not yet initialized.
    NotReady,
}

impl From<DmTargetError> for Error {
    fn from(err: DmTargetError) -> Self {
        match err {
            DmTargetError::OutOfBounds
            | DmTargetError::InvalidConfig
            | DmTargetError::DeviceNotFound => Error::InvalidArgs,
            DmTargetError::ReadOnly | DmTargetError::NotReady => Error::AccessDenied,
            DmTargetError::VerificationFailed | DmTargetError::IoError => Error::IoError,
        }
    }
}

pub type DmTargetResult<T> = Result<T, DmTargetError>;

pub trait DmTarget: Send + Sync + core::fmt::Debug {
    fn target_type(&self) -> &'static str;
    fn version(&self) -> (u32, u32, u32);
    fn table_entry(&self) -> &DmTableEntry;
    fn max_nr_segments_per_bio(&self) -> usize;
    fn map_bio(&self, bio: SubmittedBio) -> DmTargetResult<()>;
    fn status(&self) -> Option<String> {
        None
    }
}

pub fn create_target(
    entry: &DmTableEntry,
    flags: &DmDeviceFlags,
) -> DmTargetResult<Arc<dyn DmTarget>> {
    match &entry.params {
        DmTargetParams::Linear {
            device_path,
            physical_start,
        } => {
            let device = lookup_device(device_path).ok_or(DmTargetError::DeviceNotFound)?;
            Ok(Arc::new(LinearTarget {
                entry: entry.clone(),
                backing_device: device,
                physical_start: *physical_start,
                read_only: flags.read_only,
            }))
        }
        DmTargetParams::Verity {
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
        } => {
            let data_device = lookup_device(data_dev).ok_or(DmTargetError::DeviceNotFound)?;
            let hash_device = lookup_device(hash_dev).ok_or(DmTargetError::DeviceNotFound)?;
            let config = VerityConfig::new(
                *version,
                data_device,
                hash_device,
                *data_block_size as usize,
                *hash_block_size as usize,
                *num_data_blocks as usize,
                *hash_start_block as usize,
                hash_algorithm,
                root_hash,
                salt,
            )?;
            Ok(Arc::new(VerityTarget::new(
                entry.clone(),
                config,
                flags.read_only,
            )?))
        }
    }
}

fn lookup_device(device_path: &str) -> Option<Arc<dyn BlockDevice>> {
    let device_name = device_path.strip_prefix("/dev/").unwrap_or(device_path);

    aster_block::collect_all()
        .into_iter()
        .find(|device| device.name() == device_name)
}

fn ensure_read_only_policy(read_only: bool, bio_type: BioType) -> DmTargetResult<()> {
    if read_only && bio_type == BioType::Write {
        return Err(DmTargetError::ReadOnly);
    }

    Ok(())
}

fn submit_to_device(
    device: &dyn BlockDevice,
    mut bio: SubmittedBio,
    sid_offset: u64,
) -> DmTargetResult<()> {
    bio.set_sid_offset(sid_offset);
    device.enqueue(bio).map_err(map_enqueue_error)
}

fn map_enqueue_error(error: BioEnqueueError) -> DmTargetError {
    match error {
        BioEnqueueError::Refused => DmTargetError::IoError,
        BioEnqueueError::IsFull | BioEnqueueError::TooBig => DmTargetError::NotReady,
    }
}

#[derive(Debug)]
struct LinearTarget {
    entry: DmTableEntry,
    backing_device: Arc<dyn BlockDevice>,
    physical_start: u64,
    read_only: bool,
}

impl DmTarget for LinearTarget {
    fn target_type(&self) -> &'static str {
        "linear"
    }

    fn version(&self) -> (u32, u32, u32) {
        (1, 0, 0)
    }

    fn table_entry(&self) -> &DmTableEntry {
        &self.entry
    }

    fn max_nr_segments_per_bio(&self) -> usize {
        self.backing_device.metadata().max_nr_segments_per_bio
    }

    fn map_bio(&self, bio: SubmittedBio) -> DmTargetResult<()> {
        match bio.type_() {
            BioType::Flush => submit_to_device(&*self.backing_device, bio, 0),
            _ => {
                ensure_read_only_policy(self.read_only, bio.type_())?;
                submit_to_device(&*self.backing_device, bio, self.physical_start)
            }
        }
    }
}

#[derive(Debug)]
struct VerityTarget {
    entry: DmTableEntry,
    config: VerityConfig,
    status: RwLock<VerityStatus>,
    hash_cache: Mutex<BTreeMap<usize, Arc<Vec<u8>>>>,
}

impl VerityTarget {
    fn new(entry: DmTableEntry, config: VerityConfig, read_only: bool) -> DmTargetResult<Self> {
        if !read_only {
            return Err(DmTargetError::InvalidConfig);
        }

        Ok(Self {
            entry,
            config,
            status: RwLock::new(VerityStatus::default()),
            hash_cache: Mutex::new(BTreeMap::new()),
        })
    }

    fn read_verified_range(&self, offset: usize, len: usize) -> DmTargetResult<Vec<u8>> {
        let data_block_size = self.config.data_block_size;
        let first_block = offset / data_block_size;
        let last_block = (offset + len - 1) / data_block_size;
        if last_block >= self.config.num_data_blocks {
            return Err(DmTargetError::OutOfBounds);
        }

        let mut verified = Vec::with_capacity((last_block - first_block + 1) * data_block_size);
        for block_index in first_block..=last_block {
            verified.extend_from_slice(&self.read_verified_block(block_index)?);
        }

        let start = offset % data_block_size;
        Ok(verified[start..start + len].to_vec())
    }

    fn read_verified_block(&self, block_index: usize) -> DmTargetResult<Vec<u8>> {
        if block_index >= self.config.num_data_blocks {
            return Err(DmTargetError::OutOfBounds);
        }

        let data = self.read_device_block(
            &*self.config.data_device,
            block_index * self.config.data_block_size,
            self.config.data_block_size,
        )?;
        let mut expected = self.hash_data_block(&data);
        let mut current_level_block_index = block_index;

        for level in (0..self.config.hash_layout.len()).rev() {
            let hash_block_index = current_level_block_index / self.config.hashes_per_block;
            let hash_entry_index = current_level_block_index % self.config.hashes_per_block;
            let hash_block = self.read_hash_block(level, hash_block_index)?;
            let stored = self.extract_digest(&hash_block, hash_entry_index)?;
            if stored != expected.as_slice() {
                self.status.write().verification_failures += 1;
                return Err(DmTargetError::VerificationFailed);
            }

            expected = self.hash_hash_block(&hash_block);
            current_level_block_index = hash_block_index;
        }

        if expected.as_slice() != self.config.root_hash.as_slice() {
            self.status.write().verification_failures += 1;
            return Err(DmTargetError::VerificationFailed);
        }

        Ok(data)
    }

    fn read_hash_block(&self, level: usize, block_index: usize) -> DmTargetResult<Arc<Vec<u8>>> {
        let level_layout = self.config.hash_layout[level];
        if block_index >= level_layout.block_count {
            return Err(DmTargetError::OutOfBounds);
        }
        let absolute_index = level_layout.start_block + block_index;
        if let Some(cached) = self.hash_cache.lock().get(&absolute_index).cloned() {
            self.status.write().cache_hits += 1;
            return Ok(cached);
        }

        let block = Arc::new(self.read_device_block(
            &*self.config.hash_device,
            absolute_index * self.config.hash_block_size,
            self.config.hash_block_size,
        )?);
        self.hash_cache.lock().insert(absolute_index, block.clone());
        Ok(block)
    }

    fn read_device_block(
        &self,
        device: &dyn BlockDevice,
        offset: usize,
        len: usize,
    ) -> DmTargetResult<Vec<u8>> {
        let mut buffer = vec![0; len];
        device
            .read_bytes(offset, &mut buffer)
            .map_err(|_| DmTargetError::IoError)?;
        Ok(buffer)
    }

    fn hash_data_block(&self, data: &[u8]) -> Vec<u8> {
        self.config.digest.hash_data(data)
    }

    fn hash_hash_block(&self, hash_block: &[u8]) -> Vec<u8> {
        self.config.digest.hash_hash_block(hash_block)
    }

    fn extract_digest<'a>(&self, hash_block: &'a [u8], index: usize) -> DmTargetResult<&'a [u8]> {
        let start = index
            .checked_mul(self.config.digest_slot_size)
            .ok_or(DmTargetError::InvalidConfig)?;
        let end = start
            .checked_add(self.config.digest.digest_size())
            .ok_or(DmTargetError::InvalidConfig)?;
        if end > hash_block.len() {
            return Err(DmTargetError::OutOfBounds);
        }
        Ok(&hash_block[start..end])
    }

    fn populate_bio(&self, bio: &SubmittedBio, bytes: &[u8]) -> DmTargetResult<()> {
        let mut copied = 0;
        for segment in bio.segments() {
            let end = copied + segment.nbytes();
            let Some(chunk) = bytes.get(copied..end) else {
                return Err(DmTargetError::IoError);
            };
            segment
                .inner_dma_slice()
                .writer()
                .map_err(|_| DmTargetError::IoError)?
                .write(&mut ostd::mm::VmReader::from(chunk));
            copied = end;
        }

        if copied != bytes.len() {
            return Err(DmTargetError::IoError);
        }

        Ok(())
    }
}

impl DmTarget for VerityTarget {
    fn target_type(&self) -> &'static str {
        "verity"
    }

    fn version(&self) -> (u32, u32, u32) {
        (1, 0, 0)
    }

    fn table_entry(&self) -> &DmTableEntry {
        &self.entry
    }

    fn max_nr_segments_per_bio(&self) -> usize {
        self.config.data_device.metadata().max_nr_segments_per_bio
    }

    fn map_bio(&self, bio: SubmittedBio) -> DmTargetResult<()> {
        match bio.type_() {
            BioType::Flush => {
                bio.complete(BioStatus::Complete);
                Ok(())
            }
            BioType::Write => Err(DmTargetError::ReadOnly),
            BioType::Read => {
                let start_sector = bio.sid_range().start.to_raw() as usize;
                let start_offset = start_sector * SECTOR_SIZE;
                let total_len = bio.segments().iter().map(|segment| segment.nbytes()).sum();
                let verified = self.read_verified_range(start_offset, total_len)?;
                self.populate_bio(&bio, &verified)?;
                self.status.write().verified_reads += 1;
                bio.complete(BioStatus::Complete);
                Ok(())
            }
        }
    }

    fn status(&self) -> Option<String> {
        let status = self.status.read();
        Some(
            alloc::format!(
                "V {} {}",
                status.verified_reads,
                status.verification_failures
            )
            .to_string(),
        )
    }
}

#[derive(Debug)]
struct VerityConfig {
    data_device: Arc<dyn BlockDevice>,
    hash_device: Arc<dyn BlockDevice>,
    data_block_size: usize,
    hash_block_size: usize,
    num_data_blocks: usize,
    digest: DigestAlgorithm,
    root_hash: Vec<u8>,
    hashes_per_block: usize,
    digest_slot_size: usize,
    hash_layout: Vec<LevelLayout>,
}

impl VerityConfig {
    #[expect(clippy::too_many_arguments)]
    fn new(
        version: u32,
        data_device: Arc<dyn BlockDevice>,
        hash_device: Arc<dyn BlockDevice>,
        data_block_size: usize,
        hash_block_size: usize,
        num_data_blocks: usize,
        hash_start_block: usize,
        hash_algorithm: &str,
        root_hash: &str,
        salt: &str,
    ) -> DmTargetResult<Self> {
        if version != 1 {
            return Err(DmTargetError::InvalidConfig);
        }
        if data_block_size == 0
            || hash_block_size == 0
            || !data_block_size.is_multiple_of(SECTOR_SIZE)
            || !hash_block_size.is_multiple_of(SECTOR_SIZE)
            || num_data_blocks == 0
        {
            return Err(DmTargetError::InvalidConfig);
        }

        let digest = DigestAlgorithm::new(hash_algorithm, decode_hex(salt)?)?;
        let digest_size = digest.digest_size();
        let digest_slot_size = versioned_digest_slot_size(version, digest_size);
        let hashes_per_block = hash_block_size / digest_slot_size;
        if hashes_per_block == 0 {
            return Err(DmTargetError::InvalidConfig);
        }

        let hash_layout = build_hash_layout(num_data_blocks, hashes_per_block, hash_start_block)?;
        let root_hash = decode_hex(root_hash)?;
        if root_hash.len() != digest_size {
            return Err(DmTargetError::InvalidConfig);
        }

        Ok(Self {
            data_device,
            hash_device,
            data_block_size,
            hash_block_size,
            num_data_blocks,
            digest,
            root_hash,
            hashes_per_block,
            digest_slot_size,
            hash_layout,
        })
    }
}

#[derive(Debug, Clone)]
struct DigestAlgorithm {
    salt: Vec<u8>,
}

impl DigestAlgorithm {
    fn new(name: &str, salt: Vec<u8>) -> DmTargetResult<Self> {
        if name != "sha256" {
            return Err(DmTargetError::InvalidConfig);
        }

        Ok(Self { salt })
    }

    fn digest_size(&self) -> usize {
        32
    }

    fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        self.hash_bytes(data)
    }

    fn hash_hash_block(&self, data: &[u8]) -> Vec<u8> {
        self.hash_bytes(data)
    }

    fn hash_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Copy)]
struct LevelLayout {
    start_block: usize,
    block_count: usize,
}

#[derive(Debug, Default)]
struct VerityStatus {
    verified_reads: usize,
    verification_failures: usize,
    cache_hits: usize,
}

fn versioned_digest_slot_size(version: u32, digest_size: usize) -> usize {
    match version {
        0 => digest_size,
        _ => digest_size.next_power_of_two(),
    }
}

fn build_hash_layout(
    num_data_blocks: usize,
    hashes_per_block: usize,
    hash_start_block: usize,
) -> DmTargetResult<Vec<LevelLayout>> {
    let hashes_per_block =
        NonZeroUsize::new(hashes_per_block).ok_or(DmTargetError::InvalidConfig)?;
    let mut counts = vec![];
    let mut current = num_data_blocks;
    while current > 1 {
        current = current.div_ceil(hashes_per_block.get());
        counts.push(current);
    }
    if counts.is_empty() {
        counts.push(1);
    }
    counts.reverse();

    let mut next_start = hash_start_block;
    let mut layout = Vec::with_capacity(counts.len());
    for block_count in counts {
        layout.push(LevelLayout {
            start_block: next_start,
            block_count,
        });
        next_start = next_start
            .checked_add(block_count)
            .ok_or(DmTargetError::InvalidConfig)?;
    }
    Ok(layout)
}

fn decode_hex(hex: &str) -> DmTargetResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(DmTargetError::InvalidConfig);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars = hex.as_bytes();
    let mut index = 0;
    while index < chars.len() {
        let high = decode_hex_nibble(chars[index])?;
        let low = decode_hex_nibble(chars[index + 1])?;
        bytes.push((high << 4) | low);
        index += 2;
    }

    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> DmTargetResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DmTargetError::InvalidConfig),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        sync::Arc,
        vec,
        vec::Vec,
    };
    use core::sync::atomic::{AtomicU32, Ordering};

    use aster_block::{
        BlockDevice, BlockDeviceMeta,
        bio::{Bio, BioDirection, BioEnqueueError, BioStatus, BioType, SubmittedBio},
        id::Sid,
    };
    use device_id::{DeviceId, MajorId, MinorId};
    use ostd::mm::{PAGE_SIZE, io::util::HasVmReaderWriter};

    use super::{
        DmTarget, DmTargetError, LevelLayout, build_hash_layout, create_target, decode_hex,
        versioned_digest_slot_size,
    };
    use crate::{
        DmDevice,
        table::{DmDeviceFlags, DmTableEntry, DmTargetParams},
    };

    static NEXT_DEVICE_ID: AtomicU32 = AtomicU32::new(10_000);

    #[derive(Debug)]
    struct MemBlockDevice {
        id: DeviceId,
        name: String,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl MemBlockDevice {
        fn new(name: &str, bytes: Vec<u8>) -> Self {
            let minor = NEXT_DEVICE_ID.fetch_add(1, Ordering::Relaxed);
            Self {
                id: DeviceId::new(MajorId::new(240), MinorId::new(minor)),
                name: name.to_string(),
                bytes: Arc::new(Mutex::new(bytes)),
            }
        }

        fn overwrite(&self, offset: usize, bytes: &[u8]) {
            self.bytes.lock()[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
            let offset = (bio.sid_range().start.to_raw() + bio.sid_offset()) as usize * SECTOR_SIZE;
            let len: usize = bio.segments().iter().map(|segment| segment.nbytes()).sum();
            let end = offset + len;
            let storage = self.bytes.lock();
            if end > storage.len() {
                bio.complete(BioStatus::IoError);
                return Ok(());
            }

            match bio.type_() {
                BioType::Read => {
                    let mut copied = 0;
                    for segment in bio.segments() {
                        let segment_end = copied + segment.nbytes();
                        segment.inner_dma_slice().writer().unwrap().write(
                            &mut ostd::mm::VmReader::from(
                                &storage[offset + copied..offset + segment_end],
                            ),
                        );
                        copied = segment_end;
                    }
                    bio.complete(BioStatus::Complete);
                }
                BioType::Write => {
                    drop(storage);
                    let mut storage = self.bytes.lock();
                    let mut copied = 0;
                    for segment in bio.segments() {
                        let segment_end = copied + segment.nbytes();
                        storage[offset + copied..offset + segment_end]
                            .copy_from_slice(&read_segment_bytes(segment));
                        copied = segment_end;
                    }
                    bio.complete(BioStatus::Complete);
                }
                BioType::Flush => bio.complete(BioStatus::Complete),
            }
            Ok(())
        }

        fn metadata(&self) -> BlockDeviceMeta {
            BlockDeviceMeta {
                max_nr_segments_per_bio: 8,
                nr_sectors: self.bytes.lock().len() / SECTOR_SIZE,
            }
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn id(&self) -> DeviceId {
            self.id
        }
    }

    #[test]
    fn calculates_hash_layout_from_root_to_leaves() {
        let layout = build_hash_layout(64000, 128, 3).unwrap();
        assert_eq!(layout.len(), 3);
        assert_eq!(layout[0].start_block, 3);
        assert_eq!(layout[0].block_count, 1);
        assert_eq!(layout[1].block_count, 4);
        assert_eq!(layout[2].block_count, 500);
    }

    #[test]
    fn verity_target_reads_verified_data() {
        let (target, _data_device, _hash_device) = make_verity_target(false, false);
        let table = verity_table();
        let device = DmDevice::new(
            DeviceId::new(MajorId::new(253), MinorId::new(0)),
            0,
            crate::DmTable {
                name: String::from("vm_verity"),
                flags: DmDeviceFlags { read_only: true },
                entries: vec![table.clone()],
            },
            target,
        );

        let bio_segment =
            aster_block::bio::BioSegment::alloc_inner(1, 0, PAGE_SIZE, BioDirection::FromDevice);
        let bio = Bio::new(
            BioType::Read,
            Sid::from_offset(0),
            vec![bio_segment.clone()],
            None,
        );
        assert_eq!(bio.submit_and_wait(&device), Ok(BioStatus::Complete));
        assert_eq!(&read_segment_bytes(&bio_segment)[..16], b"verity-block-000");
    }

    #[test]
    fn verity_target_reads_frozen_vector_data() {
        let (target, _data_device, _hash_device) = make_frozen_verity_target();
        let table = frozen_verity_table();
        let device = DmDevice::new(
            DeviceId::new(MajorId::new(253), MinorId::new(1)),
            1,
            crate::DmTable {
                name: String::from("vm_verity_frozen"),
                flags: DmDeviceFlags { read_only: true },
                entries: vec![table.clone()],
            },
            target,
        );

        let bio_segment =
            aster_block::bio::BioSegment::alloc_inner(1, 0, PAGE_SIZE, BioDirection::FromDevice);
        let bio = Bio::new(
            BioType::Read,
            Sid::from_offset(0),
            vec![bio_segment.clone()],
            None,
        );
        assert_eq!(bio.submit_and_wait(&device), Ok(BioStatus::Complete));
        assert_eq!(&read_segment_bytes(&bio_segment)[..16], b"verity-block-000");
    }

    #[test]
    fn frozen_verity_vector_matches_generated_tree() {
        let data_blocks = sample_data_blocks();
        let tree = build_test_tree(&data_blocks, 4096, 4096, b"salt");

        assert_eq!(hex_encode(&tree.root_hash), frozen_root_hash_hex());
        assert_eq!(tree.hash_bytes, frozen_hash_bytes());
    }

    #[test]
    fn frozen_verity_vector_supports_hash_start_block_offset() {
        let (target, _data_device, _hash_device) =
            make_frozen_verity_target_with_params(frozen_root_hash_hex(), 1, 1);

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn frozen_verity_vector_fails_with_wrong_hash_start_block() {
        let (target, _data_device, _hash_device) =
            make_frozen_verity_target_with_params(frozen_root_hash_hex(), 0, 1);

        assert!(matches!(
            target_read_status(&*target),
            Err(DmTargetError::VerificationFailed)
        ));
    }

    #[test]
    fn single_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-single-data"),
            block_bytes(b"alt-verity-block-000"),
        ));
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-single-hash"),
            vec![],
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (4096 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 1,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "1c33b6333941b677749dd0f746ace0ba116d34f7fd481fe091c09c29044785be",
                ),
                salt: String::from("616c7473616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn two_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-data"),
            [
                block_bytes(b"alt2-verity-block-000"),
                block_bytes(b"alt2-verity-block-001"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "aab2dd3786a3b0196e0d749fdf2373cbf89abf29683e8a2df3317aa3304305c3",
            "c9f33f30261dd51a4f068ef8843cc3964d95bbf8fe37eb826cd5404c47a76acb",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (8192 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 2,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "683d3008d25459b71a05b174f5648ceb38d7e3d7c24c727d57867a475fe894db",
                ),
                salt: String::from("616c743273616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn two_block_frozen_verity_vector_supports_hash_start_block_offset() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-offset-data"),
            [
                block_bytes(b"alt2-verity-block-000"),
                block_bytes(b"alt2-verity-block-001"),
            ]
            .concat(),
        ));
        let mut hash_bytes = vec![0; 4096];
        hash_bytes.extend(
            decode_hex(concat!(
                "aab2dd3786a3b0196e0d749fdf2373cbf89abf29683e8a2df3317aa3304305c3",
                "c9f33f30261dd51a4f068ef8843cc3964d95bbf8fe37eb826cd5404c47a76acb",
            ))
            .unwrap(),
        );
        hash_bytes.resize(8192, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-offset-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (8192 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 2,
                hash_start_block: 1,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "683d3008d25459b71a05b174f5648ceb38d7e3d7c24c727d57867a475fe894db",
                ),
                salt: String::from("616c743273616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn two_block_frozen_verity_vector_fails_with_wrong_salt() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-wrong-salt-data"),
            [
                block_bytes(b"alt2-verity-block-000"),
                block_bytes(b"alt2-verity-block-001"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "aab2dd3786a3b0196e0d749fdf2373cbf89abf29683e8a2df3317aa3304305c3",
            "c9f33f30261dd51a4f068ef8843cc3964d95bbf8fe37eb826cd5404c47a76acb",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-double-wrong-salt-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (8192 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 2,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "683d3008d25459b71a05b174f5648ceb38d7e3d7c24c727d57867a475fe894db",
                ),
                salt: String::from("77726f6e6773616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert!(matches!(
            target_read_status(&*target),
            Err(DmTargetError::VerificationFailed)
        ));
    }

    #[test]
    fn three_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-triple-data"),
            [
                block_bytes(b"alt3-verity-block-000"),
                block_bytes(b"alt3-verity-block-001"),
                block_bytes(b"alt3-verity-block-002"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "dc5e500905b100aea12aad92681d3b062a46876efda008694d3130a95a8682d0",
            "5209920c55a3bf414d090fee68afd6b0a07cf56a5799fd7670059a253861b41b",
            "3eeb8d915b270d4cd744e1c396b1f01acc79f6de3cf91b338ea991ce4ddd476b",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-triple-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (12288 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 3,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "7b5d901744d02dcff4410b91a113ff2d4ebc06a6e11fb40455f036d9f8a4a4fb",
                ),
                salt: String::from("616c743373616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn four_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-quad-data"),
            [
                block_bytes(b"alt4-verity-block-000"),
                block_bytes(b"alt4-verity-block-001"),
                block_bytes(b"alt4-verity-block-002"),
                block_bytes(b"alt4-verity-block-003"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "a9a3172bfbadeedd796ca69a32d4c56e9b669fdaae106bef35bf1705d99d2b26",
            "566a8a0c9f4d71cc9c008ac01b4edeeca59569d19a4b600cfdb892a4e4620cb2",
            "4c71b027fedb583adf56150463c1818cf5bd6c88e02d107c31ef9463f7ffb78c",
            "9a22f893aedd30f820373e805a5c8330a2a3e5fa9cc558a82b1f235ca2ca7edb",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-quad-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (16384 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 4,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "16d0647ab2a2f0151ed5c3a58617ec4adcd7d408ec68cea7e6fdeb5becab99de",
                ),
                salt: String::from("616c743473616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn five_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-penta-data"),
            [
                block_bytes(b"alt5-verity-block-000"),
                block_bytes(b"alt5-verity-block-001"),
                block_bytes(b"alt5-verity-block-002"),
                block_bytes(b"alt5-verity-block-003"),
                block_bytes(b"alt5-verity-block-004"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "61910171ed49016c1684dbc247618699dae01eca9e7d6b679b3e641d73b8a89a",
            "f8e2a87fb97a64e449a42f75eb02b6c33102e3bf40d776c3f72fdfb935702c0b",
            "3abaaf654e8e51a02f734a57f3eea77975f82b2a2c802c127551148e8d066328",
            "bdc4b8d38501ea2d621ef55eed86c44c76c0f54502f65d6263f0d33b6cd9d814",
            "c92ac8030c1da9792bb7e7e01ce63c32514675cd9b42fd24bf9e5e5595b49cc8",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-penta-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (20480 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 5,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "46cbf586c0501ff5c1c79cdec062587e7c20930b9d78e66786ee4101df428d4c",
                ),
                salt: String::from("616c743573616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn six_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hexa-data"),
            [
                block_bytes(b"alt6-verity-block-000"),
                block_bytes(b"alt6-verity-block-001"),
                block_bytes(b"alt6-verity-block-002"),
                block_bytes(b"alt6-verity-block-003"),
                block_bytes(b"alt6-verity-block-004"),
                block_bytes(b"alt6-verity-block-005"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "5a09cda15fb644004fe8132c6badef3c6d04de534da2efcf74823a0018e63838",
            "0c0ac3eadda4fb63e425a9b345542310bd66f005b7b1d14a87ae2b8d17dd0a16",
            "c71f7ee55a48ebfce52fb0b884701ed2776fad985880adfcaef34360be2ec1bc",
            "0b2a268c34346db7f6a6ad0dbfd2756b30ddf35d2a9b10c717597fddcdf7b89a",
            "40fd0d144fb5ca868435cb3e3dcc636d6b8abac55179286c5963b1bd88cbd8f6",
            "23542108bbbb0efe0cbfabf63bdf801efa8368659e1f25bb95e4996f382e5f81",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hexa-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (24576 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 6,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "960bfe91fe1c7ff231a60cef1387b7ff52f3d3640c6c17e5895f7522668f89a6",
                ),
                salt: String::from("616c743673616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn seven_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hepta-data"),
            [
                block_bytes(b"alt7-verity-block-000"),
                block_bytes(b"alt7-verity-block-001"),
                block_bytes(b"alt7-verity-block-002"),
                block_bytes(b"alt7-verity-block-003"),
                block_bytes(b"alt7-verity-block-004"),
                block_bytes(b"alt7-verity-block-005"),
                block_bytes(b"alt7-verity-block-006"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "81a44270bd7d82f0b34bb26a9ddf17f94ad2bd84ba54691337e1448ce3ba5c4c",
            "095c36dcae59df50e5bb82b4724f1f5cd0d1845b832120c1b26ec594c4f9ef02",
            "a410c6cfd8cc9f33f852e325bbead0a0e1ff67a7bc1851dae795188d8f38080d",
            "372db0a284e92297cc2677ee19b352a32138593119dc83b6e9049dfc342d50be",
            "ac7d05a57d2597eae61b567dc08a657ce5301f502c869ae61d5c8b85e750d050",
            "8c548805ebbe4547234f389d38bec34aefcd58af06a5e79e105b698d87a9d1a3",
            "ea147ae1c3cc7d83451ead2f9a0b8e2d83f21dbc5b4a6c40629204f0e31f29a2",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hepta-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (28672 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 7,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "1bf72587f6a04e6ead5a3bd4990482bf27aaaed4a0864863965d662b6e18cb66",
                ),
                salt: String::from("616c743773616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn eight_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-octa-data"),
            [
                block_bytes(b"alt8-verity-block-000"),
                block_bytes(b"alt8-verity-block-001"),
                block_bytes(b"alt8-verity-block-002"),
                block_bytes(b"alt8-verity-block-003"),
                block_bytes(b"alt8-verity-block-004"),
                block_bytes(b"alt8-verity-block-005"),
                block_bytes(b"alt8-verity-block-006"),
                block_bytes(b"alt8-verity-block-007"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "89b8f5d987cc672f838a8cec53613f14a7032fc3a16f7aa8eab509743396b0d3",
            "57e53ef8a3cb9ba988496451f713ef80054eab6a7155ed602c8c9f200438c395",
            "865acb923ae4fc5cef9156c39361ddc74007cce4320d0f3af3c08f9053df6b58",
            "3f13f19dcf00b6e6929d68e2e2156cbf667f0dbf04ac5b269f94187159562c3f",
            "4e4dad136ff2f28716591632c900b1b382786cd4d71f20d39d99e68e698ee2ed",
            "3d9dd25fb5746d8f1becb895230ad08a49ec05976353acfa94d71c3a90ede6df",
            "4cf712394b1e005a6e33fc2b073a53637f782d9f664c90bf4a4594b84df350cf",
            "76e0191b684a9231a0ee5d14d712585f39f197e67118304080f4f79ab5854fce",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-octa-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (32768 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 8,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "30439c3b787674c8701d0aba3279df88f1b3b5d91d3e87fa0c447eeae31b51d5",
                ),
                salt: String::from("616c743873616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn nine_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-nona-data"),
            [
                block_bytes(b"alt9-verity-block-000"),
                block_bytes(b"alt9-verity-block-001"),
                block_bytes(b"alt9-verity-block-002"),
                block_bytes(b"alt9-verity-block-003"),
                block_bytes(b"alt9-verity-block-004"),
                block_bytes(b"alt9-verity-block-005"),
                block_bytes(b"alt9-verity-block-006"),
                block_bytes(b"alt9-verity-block-007"),
                block_bytes(b"alt9-verity-block-008"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "c73e64451405553d8ee6e5d9a87d2cbab805e8688f9cf3a24b196c768f264dab",
            "12c9ef397c353ac9486a716e9b001bece49abc7fcb5407209a3bdbeb158a5556",
            "b5b0c80267200aae18275a3707dcbaaa03e7f6821be967afff542c4b74459fe1",
            "6bc6e4aad323b93ede2f5be97e1076c676c679c8ec694030405521182acd396b",
            "dda67868f5a29112826ed7a763144b7e4a2157f3a92c1df558f92c88fd16cb17",
            "0b1304ca30aa5975ce510897cb92e8019f816b8fcf17b570f902018828053427",
            "3e6cc9aeba545500f58fd4c8fcc8e917996138a7aaf9a144de1ee4d7023c599a",
            "e2eb01fcde938c0062d022404a0dc7c849e0548621616456e9f26c2d5f423c47",
            "a96095f8571bfc1c1f6fe087f2da2c51b51a6a5849713aa86b65bf235cce3b6e",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-nona-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (36864 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 9,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "18bc4ac1e24de82f5b189d8eb18de645d30177ec02b74fd9a10332517facc0a5",
                ),
                salt: String::from("616c743973616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn ten_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-deca-data"),
            [
                block_bytes(b"alt10-verity-block-000"),
                block_bytes(b"alt10-verity-block-001"),
                block_bytes(b"alt10-verity-block-002"),
                block_bytes(b"alt10-verity-block-003"),
                block_bytes(b"alt10-verity-block-004"),
                block_bytes(b"alt10-verity-block-005"),
                block_bytes(b"alt10-verity-block-006"),
                block_bytes(b"alt10-verity-block-007"),
                block_bytes(b"alt10-verity-block-008"),
                block_bytes(b"alt10-verity-block-009"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "ea7936613e999fceaa6bd43a33998123a9c2d63d8c212343a95a7f333d077aa5",
            "0d59b331fca3313bfb122df50a14462d6f964fc37a26767207870a1142efcbd1",
            "539e97ff44f7a19ead669f83c4e7eeb9ca5af3ef66a05e62d9bda12a15cafc51",
            "516b64dbc058dcec9ed63565b4a038c1a53bfa18f8c6666ceae32ce97478779a",
            "337d505cc572b73cfbc99fa60e2025d0fe428719c479e343e9cde237805715ed",
            "9a7cc3a192f295270bf0f69163d591b9f9b9e72114b961feb90c3e1527d1d8fb",
            "dc0cce1335a6134c0d72cab0486cef80fb85586a8aa232b127da6dfb2f96baa0",
            "0ab450af6f15df7dcb5201f98715c6d51ac1f2047be01bc77a7eb15d5803014a",
            "2e1689eb6695d33ddbcaac31cf5493ee11bc94e271813f48606ef89dd2088075",
            "a1ad14a37fc6a41f9c8091e92ffd92543bea14b89f5738f781fbbe6e4924f516",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-deca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (40960 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 10,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "f95f08c2196f61b468f471e5d71af379dfec032cd1a00a1efab4e16a24f17055",
                ),
                salt: String::from("616c74313073616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn eleven_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hendeca-data"),
            [
                block_bytes(b"alt11-verity-block-000"),
                block_bytes(b"alt11-verity-block-001"),
                block_bytes(b"alt11-verity-block-002"),
                block_bytes(b"alt11-verity-block-003"),
                block_bytes(b"alt11-verity-block-004"),
                block_bytes(b"alt11-verity-block-005"),
                block_bytes(b"alt11-verity-block-006"),
                block_bytes(b"alt11-verity-block-007"),
                block_bytes(b"alt11-verity-block-008"),
                block_bytes(b"alt11-verity-block-009"),
                block_bytes(b"alt11-verity-block-010"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "8078a4f2ca85be2cc1df66a29b071a8074c2ea1e423d61c247d82fe6fd9ef082",
            "22421dd8863c53b5d3d5719c315e44833b77842a3e0cc7167af523375aea039a",
            "afeb756ac30079f1ab2c4ea7ba9445c623c8208aac20a377d2b5a1f23e31aedb",
            "9bbeb7e62231fcdb68041a6f2d9c3d27f1a0359b52d9401b62e5dc5102c4b0e0",
            "5ed819f6e46d0bd87c4e6efc1285180ce665d3072878d6dcf2bce00f40787caa",
            "1d4c82630a7f3d4312a5817d005f8c6c76192e44828cb685c8228a275de57a8d",
            "c0cff0b0cbb4e23c44ee94ef3ee2fe135a46a06b3483812c0b3d7af689954e54",
            "9b9fed4eee8d47e7922366f1ae65f99e660fe6e796fe46da7b99a64ca1afb05f",
            "42b8e25961e98d824500bb313e16bb63b851c89f428dcfb005ab9ca99158d3aa",
            "b10e0512f2538cf63e3d80d447bc7df7e3f3160c778890e9cbfcaef0e8286a97",
            "e69cbade74b89263164a34462e6a2e5535ef3b087c14eeb9fcdb012b690b1835",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hendeca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (45056 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 11,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "b68af56713bf0a0cb96494374f88dc3f43dc002ee8fbba2c336e589190bb7fe8",
                ),
                salt: String::from("616c74313173616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn twelve_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-dodeca-data"),
            [
                block_bytes(b"alt12-verity-block-000"),
                block_bytes(b"alt12-verity-block-001"),
                block_bytes(b"alt12-verity-block-002"),
                block_bytes(b"alt12-verity-block-003"),
                block_bytes(b"alt12-verity-block-004"),
                block_bytes(b"alt12-verity-block-005"),
                block_bytes(b"alt12-verity-block-006"),
                block_bytes(b"alt12-verity-block-007"),
                block_bytes(b"alt12-verity-block-008"),
                block_bytes(b"alt12-verity-block-009"),
                block_bytes(b"alt12-verity-block-010"),
                block_bytes(b"alt12-verity-block-011"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "5d88cbcd13d536f5d3f75be79486b77bfc628b6038634934cd743705225b2f80",
            "0ab4596b3e6918bc2dc89960e2820a61c9e8b5d0a265261acc4b0746b76a4733",
            "fe2d390b5c8c519e8e2811bc233f9cb560413aaec01952dc182ec5efa496a048",
            "6f8e55a684ec9a16aece9775bcc1ef2c2961da9fcfdf50d8a3b1494286f253eb",
            "5e5ef58c016b2b05b16b40b0d2c83b7790296e837b70f302b86ec4bea0209ae3",
            "017b067cd57985de8374ad5fe457b53d7df5955c2cf03bbe8acc2ec1774bb253",
            "f5b585a4b2ac53ddbc56a18f5185a3444f16f9f2f346dc16012c915cf7bb90ec",
            "e6c4267ae5501abc5707c406747fef6cb5b3c9c9d4d9e8c2b7b1bd0bff5e7eff",
            "46c502eadff58807b259f02e45d4a029f9fa8292816383ce923e69642e0828cd",
            "3817eea9bd601c87cdc3e551ee4f89924762a1d6ef3d4e9b81cf5d9d71628352",
            "e3fcf53c54d9377b127c2b21814dc5f6c159175ad9811360fbc982e55f230f56",
            "008e6a8d97380df602fdbc1a68a75f6d885f7d0c912486b529bae5af850d71ed",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-dodeca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (49152 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 12,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "f64ed746f2d6a31debdff2d57ee160aa712658d4c8f18f0fb06abe7d469a92ca",
                ),
                salt: String::from("616c74313273616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn thirteen_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-trideca-data"),
            [
                block_bytes(b"alt13-verity-block-000"),
                block_bytes(b"alt13-verity-block-001"),
                block_bytes(b"alt13-verity-block-002"),
                block_bytes(b"alt13-verity-block-003"),
                block_bytes(b"alt13-verity-block-004"),
                block_bytes(b"alt13-verity-block-005"),
                block_bytes(b"alt13-verity-block-006"),
                block_bytes(b"alt13-verity-block-007"),
                block_bytes(b"alt13-verity-block-008"),
                block_bytes(b"alt13-verity-block-009"),
                block_bytes(b"alt13-verity-block-010"),
                block_bytes(b"alt13-verity-block-011"),
                block_bytes(b"alt13-verity-block-012"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "50cf274b5a8b343a0d2f03f80c36df206764e895e569f1d2bed63196f9b65b71",
            "b55220fa9ef89e78393b696aab6ce9a32cd91441c5b96de0fc90d477b0ea484a",
            "02fa6cc18944395e876b1d7f3923d56956c5cff740c83ac3d491e0eef7fde9ba",
            "aa4a758cde7cceee74e928eba2e51b0b94d4081b829c278571c770c76e4fa205",
            "6fc8436453d41645ee5ff6d4bd02d247118e5f3defc3f017f6d17b722d03f1a2",
            "4d8ce639afdcc6844611bd925c80f5a800db7fdd872b3548c62e121b79d74cfd",
            "902d44c6e5d230013402e1612de1cb2a4ab23b920d5b4b2a55115bc069fe7aaa",
            "297597ba70fc574a27ba194d1ca4e186253527f38668838f6bd0913cff906cd8",
            "21dfe61a5610bddeb7dab53e112361d8709aac428aabd2655118568324cdec20",
            "2635c2267a48ca0c5822a8825688a274ad4ef590e8df331fe3349c73d53daa6f",
            "b19ae5c81f97f5c1bb3728c27c8e638f5db209646d79d4a2c86687ba4e00ce38",
            "6ab70e05871d2af8c576ec6c9d82b931d1462675f753315baa63fb2e15a3cfb4",
            "bb0eaa57af6dc7de1fccd31c6aabda15d4601a0d2692ce61734595159d3956aa",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-trideca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (53248 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 13,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "aafd5508c055680ddb02b71a2944071c46be913b7e7338fc3b5e2382f8cb0260",
                ),
                salt: String::from("616c74313373616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn fourteen_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-tetradeca-data"),
            [
                block_bytes(b"alt14-verity-block-000"),
                block_bytes(b"alt14-verity-block-001"),
                block_bytes(b"alt14-verity-block-002"),
                block_bytes(b"alt14-verity-block-003"),
                block_bytes(b"alt14-verity-block-004"),
                block_bytes(b"alt14-verity-block-005"),
                block_bytes(b"alt14-verity-block-006"),
                block_bytes(b"alt14-verity-block-007"),
                block_bytes(b"alt14-verity-block-008"),
                block_bytes(b"alt14-verity-block-009"),
                block_bytes(b"alt14-verity-block-010"),
                block_bytes(b"alt14-verity-block-011"),
                block_bytes(b"alt14-verity-block-012"),
                block_bytes(b"alt14-verity-block-013"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "0acd39ced69741ca2e919cc85f61e7746cd5b5d99871f9387b89bcf9bf42eed2",
            "dc0e9a40886c537f732fcb46b21ee3f6dfdcb25e2fc939e6197f231fb0c9f949",
            "147e50ec3f9db07f29867371eded952f6cd304ff83da8737cb61beda7402d538",
            "8a35b3d3e1ee160ed52b1d871b68712c7c41e3023c2cc8ca73464b6cd4dec9e1",
            "262094d289b7788e563b0b2c16c18d3f8b7879ae1ea04c9fbd343ca6da773736",
            "7d072beb9fb864d5b298d0946b13422e150456823fdd92235cea845d7c5cb3ca",
            "25b8657f79bf66534572ae03f49f257d050312c33eb5b8c62ee54bc8f86706b4",
            "44e4bbdda259805891ffb1fa178cc733e04c2d7e98b685444d5fb8cef66b4e83",
            "cedb802376d54dbc95f7bf1c9277fe0971bf7896856eb27ed895839bffce4054",
            "c41b7aea997e8cbd28d9ea705843770c64ec6b7052bb7012c4733b007d72fa7f",
            "5ddd463a20fd0062845074fb298fdb2a0bd9d8d05097064313bd3cf0667b1a6c",
            "cb3dec297c498b58ed13a56834ddd4058f0e6055029831d2d3d5975812e8686b",
            "c242655676bd59d13f763a9ec27278263226cff4092a98ecb6fda83cb20b9bf4",
            "d8a07f6e22629fddc76039584334fa67d72ca46e117a0eda31106b8cdc9e3536",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-tetradeca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (57344 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 14,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "8405cef46c6434b124cca6f7c58bd15d14c3d0674e64fbc7dee4852ee23d7a72",
                ),
                salt: String::from("616c74313473616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn fifteen_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-pentadeca-data"),
            [
                block_bytes(b"alt15-verity-block-000"),
                block_bytes(b"alt15-verity-block-001"),
                block_bytes(b"alt15-verity-block-002"),
                block_bytes(b"alt15-verity-block-003"),
                block_bytes(b"alt15-verity-block-004"),
                block_bytes(b"alt15-verity-block-005"),
                block_bytes(b"alt15-verity-block-006"),
                block_bytes(b"alt15-verity-block-007"),
                block_bytes(b"alt15-verity-block-008"),
                block_bytes(b"alt15-verity-block-009"),
                block_bytes(b"alt15-verity-block-010"),
                block_bytes(b"alt15-verity-block-011"),
                block_bytes(b"alt15-verity-block-012"),
                block_bytes(b"alt15-verity-block-013"),
                block_bytes(b"alt15-verity-block-014"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "284d6a0f7621b851630f9c7fb1dec2fcafe441030941caa64b7b1f2c910222d0",
            "dafcf8ed8a7ac92cfaa79ab03ca09ac0e14b36032a427fb70752db15e9738c2f",
            "d00c8d134e969271925915036a121a27d02e2edb8f1e0af423875e2f06b622e8",
            "d8d645a4029f7af8756ade4e9636544e56f9ddb345e5709522fca3cc0dc0d6f8",
            "4aab973d915ba89a3057da582816d7559b1de27dbaef57ce28cdba763df76572",
            "fe1908c5a1afd87032408ae180683b1336c937fd8dc3c19cfa467541e6dfb16f",
            "a6359b3d5842f1368d5cef91e8e211d885cc8dc402ea91d2c95d697dc11a85c6",
            "b8356b74c4f0e59628f5dda4148e2698736ba6a53841302576f298dfaa7e1ee8",
            "db2bdad24074bf1d1039dc84298840177f1c7099ec083058a64b62592c1e348b",
            "1337e18a261b864deee3b666d7767f3bced1be1c30f703ab05622eaa309354ee",
            "e60115b867c7a9907bb9d31392c33e66bebfd5c5ae9b14625946457e85af913d",
            "5700ec098c7f3cf6def5533611e8101b639fa75d684b35f49ed17cc50c29ac44",
            "0aa256b88c87639556e5c1763dfa904c72d0ae683c0855acb9b891f984e02dff",
            "8c60c7ec305b51c19840cdb3d0f62c1861c8b828216b573808d71a147abd314d",
            "31d96239cf3978ffce3cea7cf4ec3202276b775f0f4a74e3d436361e09f4dcd7",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-pentadeca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (61440 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 15,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "7a42fb26fbc15a55afbc13f06deeb5676a0c53daddaa31c7beba5f5ccf4afc7e",
                ),
                salt: String::from("616c74313573616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn sixteen_block_frozen_verity_vector_matches_linux_veritysetup() {
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hexadeca-data"),
            [
                block_bytes(b"alt16-verity-block-000"),
                block_bytes(b"alt16-verity-block-001"),
                block_bytes(b"alt16-verity-block-002"),
                block_bytes(b"alt16-verity-block-003"),
                block_bytes(b"alt16-verity-block-004"),
                block_bytes(b"alt16-verity-block-005"),
                block_bytes(b"alt16-verity-block-006"),
                block_bytes(b"alt16-verity-block-007"),
                block_bytes(b"alt16-verity-block-008"),
                block_bytes(b"alt16-verity-block-009"),
                block_bytes(b"alt16-verity-block-010"),
                block_bytes(b"alt16-verity-block-011"),
                block_bytes(b"alt16-verity-block-012"),
                block_bytes(b"alt16-verity-block-013"),
                block_bytes(b"alt16-verity-block-014"),
                block_bytes(b"alt16-verity-block-015"),
            ]
            .concat(),
        ));
        let mut hash_bytes = decode_hex(concat!(
            "2228c255df4b709fa4b5ca8ec545916c4a11a57dbf88dea28a2b99dd4f92cdd1",
            "a3ce01cac1229f44735bd35c92368da69912ea6af57ddc12cfc5cd22396e9a97",
            "747ce4f8db069c38fa6c3405879b08fcec9ae082fa0354a2719031f5c2a13169",
            "83b9292bd887b38959d1fa7024ac6f1a810468a36e46f36ed7577fc172be37cc",
            "b838b8c9da02a628302f09b79d89ff40fb1ee7b920d245069cbffd91fde3d1de",
            "5068ac3cee8e040b00dcc4837f74c5e7557940e3c2ed84dfa1c38be84036d5c3",
            "fd6b1476abbb1a3b0fcac8ad235016bd8bc1afd9ba6b24f5fd1f46e0d5b24fa2",
            "95143d51b311ca1637b9c941b15e3b41262416f1f9604b3350b95a677d221cde",
            "f566e7a7eb82722b54737fe28048bd6afb023f3cd30ac6d6a88ed4a5598ccd50",
            "1dbb605243f337956f616cadfe4292a364a7647166e16c1e836f34f955f9bfef",
            "f8e23e671f0fc3bc630b2b9618a7d6853d9d03ba1db309a07a6762ddea607d45",
            "b06f21edf34fa9489d65026f55cf60d9e186e48f4a2d74584e0414cabce0bbce",
            "8e2cbdd23966296417c0aad0569f9595cbdae3663e4a4b470ffc63fe94ec7ce8",
            "a45363c1c8ae85d363490f59990f1b090c80c42746157daf79e03ae098f5d9b3",
            "194c114685e04c3d67bd375e68ffd2858bc9c56de89af11c971831f8935e7b94",
            "e3c2cdeb20d54c1f3674442c3e6283614852d1f714b9c362f793f508b9903a59",
        ))
        .unwrap();
        hash_bytes.resize(4096, 0);
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-hexadeca-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (65536 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: 16,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(
                    "fec791a03e6333a0004665ee1ff86fd9530c2080eae0505bd4c79a99dae40df2",
                ),
                salt: String::from("616c74313673616c74"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        assert_eq!(target_read_status(&*target), Ok(()));
    }

    #[test]
    fn frozen_verity_target_reads_across_multiple_data_blocks() {
        let device = frozen_verity_device(2);
        let segments = submit_read(&device, 0, &[PAGE_SIZE, PAGE_SIZE]);

        assert_eq!(&segments[0][..16], b"verity-block-000");
        assert_eq!(&segments[1][..16], b"verity-block-001");
    }

    #[test]
    fn frozen_verity_vector_fails_with_corrupted_hash_block_padding() {
        let (target, _data_device, hash_device) = make_frozen_verity_target();
        hash_device.overwrite(96, b"X");

        assert!(matches!(
            target_read_status(&*target),
            Err(DmTargetError::VerificationFailed)
        ));
    }

    #[test]
    fn verity_target_fails_on_corrupted_data() {
        let (target, _data_device, data_hash) = make_verity_target(true, false);
        assert!(matches!(
            target_read_status(&*target),
            Err(DmTargetError::VerificationFailed)
        ));
        drop(data_hash);
    }

    #[test]
    fn verity_target_fails_on_corrupted_hash() {
        let (target, _data_device, _hash_device) = make_verity_target(false, true);
        assert!(matches!(
            target_read_status(&*target),
            Err(DmTargetError::VerificationFailed)
        ));
    }

    #[test]
    fn rejects_unsupported_hash_algorithm() {
        let data_device = Arc::new(MemBlockDevice::new("alg-data", vec![0; 4096]));
        let hash_device = Arc::new(MemBlockDevice::new("alg-hash", vec![0; 4096]));
        let result = super::VerityConfig::new(
            1,
            data_device,
            hash_device,
            4096,
            4096,
            1,
            0,
            "sha1",
            "00",
            "00",
        );

        assert_eq!(result.unwrap_err(), DmTargetError::InvalidConfig);
    }

    fn target_read_status(target: &dyn DmTarget) -> Result<(), DmTargetError> {
        let bio_segment =
            aster_block::bio::BioSegment::alloc_inner(1, 0, PAGE_SIZE, BioDirection::FromDevice);
        let bio = Bio::new(BioType::Read, Sid::from_offset(0), vec![bio_segment], None);
        bio.submit_and_wait(&DumbTargetDevice(target)).unwrap();
        Ok(())
    }

    fn submit_read(
        device: &dyn BlockDevice,
        start_sector: u64,
        segment_lengths: &[usize],
    ) -> Vec<Vec<u8>> {
        let segments: Vec<_> = segment_lengths
            .iter()
            .map(|length| {
                aster_block::bio::BioSegment::alloc_inner(1, 0, *length, BioDirection::FromDevice)
            })
            .collect();
        let bio = Bio::new(
            BioType::Read,
            Sid::from_offset(start_sector),
            segments.clone(),
            None,
        );

        assert_eq!(bio.submit_and_wait(device), Ok(BioStatus::Complete));

        segments.iter().map(read_segment_bytes).collect()
    }

    struct DumbTargetDevice<'a>(&'a dyn DmTarget);

    impl BlockDevice for DumbTargetDevice<'_> {
        fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
            self.0.map_bio(bio).map_err(|_| BioEnqueueError::Refused)
        }

        fn metadata(&self) -> BlockDeviceMeta {
            BlockDeviceMeta {
                max_nr_segments_per_bio: 8,
                nr_sectors: 8,
            }
        }

        fn name(&self) -> &str {
            "dummy"
        }

        fn id(&self) -> DeviceId {
            DeviceId::new(MajorId::new(250), MinorId::new(0))
        }
    }

    fn make_verity_target(
        corrupt_data: bool,
        corrupt_hash: bool,
    ) -> (Arc<dyn DmTarget>, Arc<MemBlockDevice>, Arc<MemBlockDevice>) {
        let data_blocks = sample_data_blocks();
        let tree = build_test_tree(&data_blocks, 4096, 4096, b"salt");
        let data_bytes = data_blocks.concat();
        let hash_bytes = tree.hash_bytes.clone();
        let data_device = Arc::new(MemBlockDevice::new(&unique_name("verity-data"), data_bytes));
        let hash_device = Arc::new(MemBlockDevice::new(&unique_name("verity-hash"), hash_bytes));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        if corrupt_data {
            data_device.overwrite(0, b"X");
        }
        if corrupt_hash {
            hash_device.overwrite(tree.layout.last().unwrap().start_block * 4096, b"X");
        }

        let entry = DmTableEntry {
            logical_start: 0,
            length: (data_blocks.len() * 4096 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: data_blocks.len() as u32,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: hex_encode(&tree.root_hash),
                salt: hex_encode(b"salt"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        (target, data_device, hash_device)
    }

    fn verity_table() -> DmTableEntry {
        let data_blocks = sample_data_blocks();
        let tree = build_test_tree(&data_blocks, 4096, 4096, b"salt");
        DmTableEntry {
            logical_start: 0,
            length: (data_blocks.len() * 4096 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: String::from("unused"),
                hash_dev: String::from("unused"),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: data_blocks.len() as u32,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: hex_encode(&tree.root_hash),
                salt: hex_encode(b"salt"),
            },
        }
    }

    fn frozen_verity_device(minor: u32) -> DmDevice {
        let (target, _data_device, _hash_device) = make_frozen_verity_target();
        let table = frozen_verity_table();

        DmDevice::new(
            DeviceId::new(MajorId::new(253), MinorId::new(minor)),
            minor,
            crate::DmTable {
                name: String::from("vm_verity_frozen"),
                flags: DmDeviceFlags { read_only: true },
                entries: vec![table],
            },
            target,
        )
    }

    fn make_frozen_verity_target() -> (Arc<dyn DmTarget>, Arc<MemBlockDevice>, Arc<MemBlockDevice>)
    {
        make_frozen_verity_target_with_params(frozen_root_hash_hex(), 0, 0)
    }

    fn make_frozen_verity_target_with_params(
        root_hash: &str,
        hash_start_block: usize,
        hash_prefix_blocks: usize,
    ) -> (Arc<dyn DmTarget>, Arc<MemBlockDevice>, Arc<MemBlockDevice>) {
        let data_blocks = sample_data_blocks();
        let data_bytes = data_blocks.concat();
        let hash_bytes = prefixed_frozen_hash_bytes(hash_prefix_blocks);
        let data_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-frozen-data"),
            data_bytes,
        ));
        let hash_device = Arc::new(MemBlockDevice::new(
            &unique_name("verity-frozen-hash"),
            hash_bytes,
        ));
        aster_block::register(data_device.clone()).unwrap();
        aster_block::register(hash_device.clone()).unwrap();

        let entry = DmTableEntry {
            logical_start: 0,
            length: (data_blocks.len() * 4096 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: format!("/dev/{}", data_device.name()),
                hash_dev: format!("/dev/{}", hash_device.name()),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: data_blocks.len() as u32,
                hash_start_block: hash_start_block as u32,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(root_hash),
                salt: hex_encode(b"salt"),
            },
        };
        let target = create_target(&entry, &DmDeviceFlags { read_only: true }).unwrap();

        (target, data_device, hash_device)
    }

    fn frozen_verity_table() -> DmTableEntry {
        let data_blocks = sample_data_blocks();
        DmTableEntry {
            logical_start: 0,
            length: (data_blocks.len() * 4096 / SECTOR_SIZE) as u64,
            target_name: String::from("verity"),
            params: DmTargetParams::Verity {
                version: 1,
                data_dev: String::from("unused"),
                hash_dev: String::from("unused"),
                data_block_size: 4096,
                hash_block_size: 4096,
                num_data_blocks: data_blocks.len() as u32,
                hash_start_block: 0,
                hash_algorithm: String::from("sha256"),
                root_hash: String::from(frozen_root_hash_hex()),
                salt: hex_encode(b"salt"),
            },
        }
    }

    fn frozen_root_hash_hex() -> &'static str {
        "71caa9632cfdd78bd94b03198ba93cefb8ad7babc510e357028e8d167ba16a47"
    }

    fn frozen_hash_bytes() -> Vec<u8> {
        let mut bytes = decode_hex(concat!(
            "4a4bc0f86f12a8f082b3eacd6d098fa5225bd02486979375c577a8f3c55f6773",
            "dbe8caef84f34020f259487cd1c9238b449cd2f75e670eb8e1e7984c092f54a0",
            "6faea72b6dee0c3a21dd48ac5364be40e6fa4fe3d099b691b13e7e09b523dd53",
        ))
        .unwrap();
        bytes.resize(4096, 0);
        bytes
    }

    fn prefixed_frozen_hash_bytes(prefix_blocks: usize) -> Vec<u8> {
        let mut bytes = vec![0; prefix_blocks * 4096];
        bytes.extend_from_slice(&frozen_hash_bytes());
        bytes
    }

    fn sample_data_blocks() -> Vec<Vec<u8>> {
        vec![
            block_bytes(b"verity-block-000"),
            block_bytes(b"verity-block-001"),
            block_bytes(b"verity-block-002"),
        ]
    }

    fn block_bytes(prefix: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
    }

    #[derive(Debug)]
    struct TestTree {
        layout: Vec<LevelLayout>,
        hash_bytes: Vec<u8>,
        root_hash: Vec<u8>,
    }

    fn build_test_tree(
        data_blocks: &[Vec<u8>],
        data_block_size: usize,
        hash_block_size: usize,
        salt: &[u8],
    ) -> TestTree {
        let digest_size = 32;
        let slot_size = versioned_digest_slot_size(1, digest_size);
        let hashes_per_block = hash_block_size / slot_size;
        let layout = build_hash_layout(data_blocks.len(), hashes_per_block, 0).unwrap();
        let mut levels = Vec::new();
        let mut current_hashes: Vec<Vec<u8>> = data_blocks
            .iter()
            .map(|block| salted_sha256(salt, block))
            .collect();

        while current_hashes.len() > 1 {
            let mut blocks = Vec::new();
            for chunk in current_hashes.chunks(hashes_per_block) {
                let mut block = vec![0; hash_block_size];
                for (index, digest) in chunk.iter().enumerate() {
                    let start = index * slot_size;
                    block[start..start + digest.len()].copy_from_slice(digest);
                }
                blocks.push(block);
            }
            current_hashes = blocks
                .iter()
                .map(|block| salted_sha256(salt, block))
                .collect();
            levels.push(blocks);
        }
        let root_hash = current_hashes.pop().unwrap();
        levels.reverse();

        let mut hash_bytes = Vec::new();
        for level in &levels {
            for block in level {
                hash_bytes.extend_from_slice(block);
            }
        }

        let _ = data_block_size;
        TestTree {
            layout,
            hash_bytes,
            root_hash,
        }
    }

    fn salted_sha256(salt: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut output = String::new();
        for byte in bytes {
            output.push(nibble_to_hex(byte >> 4));
            output.push(nibble_to_hex(byte & 0x0f));
        }
        output
    }

    fn nibble_to_hex(nibble: u8) -> char {
        match nibble {
            0..=9 => (b'0' + nibble) as char,
            _ => (b'a' + nibble - 10) as char,
        }
    }

    fn read_segment_bytes(segment: &aster_block::bio::BioSegment) -> Vec<u8> {
        let mut bytes = vec![0; segment.nbytes()];
        segment.inner_dma_slice().read_bytes(0, &mut bytes).unwrap();
        bytes
    }

    fn unique_name(prefix: &str) -> String {
        let id = NEXT_DEVICE_ID.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }
}
