// SPDX-License-Identifier: MPL-2.0

use core::{fmt::Debug, mem::size_of};

use bitflags::bitflags;
use id_alloc::IdAlloc;
use int_to_c_enum::TryFromInt;

use super::IrtEntryHandle;
use crate::{
    mm::{FrameAllocOptions, Segment, UntypedMem, PAGE_SIZE},
    sync::{LocalIrqDisabled, SpinLock},
};

#[expect(dead_code)]
#[derive(Debug)]
enum ExtendedInterruptMode {
    XApic,
    X2Apic,
}

struct IntRemappingMeta;
crate::impl_untyped_frame_meta_for!(IntRemappingMeta);

pub struct IntRemappingTable {
    num_entries: u16,
    extended_interrupt_mode: ExtendedInterruptMode,
    segment: Segment<IntRemappingMeta>,
    /// A lock that prevents concurrent modification of entries.
    modification_lock: SpinLock<(), LocalIrqDisabled>,
    /// An allocator that allocates indexes to unused entries.
    allocator: SpinLock<IdAlloc, LocalIrqDisabled>,
}

impl IntRemappingTable {
    pub fn alloc(&'static self) -> Option<IrtEntryHandle> {
        let index = self.allocator.lock().alloc()?;
        Some(IrtEntryHandle {
            index: index as u16,
            table: self,
        })
    }

    /// Creates an Interrupt Remapping Table with one page.
    pub(super) fn new() -> Self {
        const NUM_PAGES: usize = 1;

        let segment = FrameAllocOptions::new()
            .alloc_segment_with(NUM_PAGES, |_| IntRemappingMeta)
            .unwrap();
        let num_entries = (NUM_PAGES * PAGE_SIZE / size_of::<u128>())
            .try_into()
            .unwrap();

        Self {
            num_entries,
            extended_interrupt_mode: ExtendedInterruptMode::X2Apic,
            segment,
            modification_lock: SpinLock::new(()),
            allocator: SpinLock::new(IdAlloc::with_capacity(num_entries as usize)),
        }
    }

    /// Sets the entry in the Interrupt Remapping Table.
    pub(super) fn set_entry(&self, index: u16, entry: IrtEntry) {
        let _guard = self.modification_lock.lock();

        let [lower, upper] = entry.as_raw_u64();

        let offset = (index as usize) * size_of::<u128>();
        // Write a zero as the lower bits first to clear the present bit.
        self.segment
            .writer()
            .skip(offset)
            .write_once(&0u64)
            .unwrap();
        // Write the upper bits first (which keeps the present bit unset)
        self.segment
            .writer()
            .skip(offset + size_of::<u64>())
            .write_once(&upper)
            .unwrap();
        self.segment
            .writer()
            .skip(offset)
            .write_once(&lower)
            .unwrap();
    }

    /// Encodes the value written into the Interrupt Remapping Table Register.
    pub(crate) fn encode(&self) -> u64 {
        let mut encoded = self.segment.start_paddr() as u64;

        // Bit Range 11 - Extended Interrupt Mode Enable (EIME)
        encoded |= match self.extended_interrupt_mode {
            ExtendedInterruptMode::XApic => 0,
            ExtendedInterruptMode::X2Apic => 1 << 11,
        };

        // Bit Range 3:0 - Size (S)
        encoded |= {
            assert!(self.num_entries.is_power_of_two());
            // num_entries = 2^(size+1)
            let size = self.num_entries.trailing_zeros().checked_sub(1).unwrap();
            assert!(size <= 15);
            size as u64
        };

        encoded
    }
}

/// The type of validation that must be performed by the interrupt-remapping hardware.
#[derive(Debug, TryFromInt)]
#[repr(u32)]
pub enum SourceValidationType {
    /// No requester-id verification is required.
    Disable = 0b00,
    /// Verify requester-id in the interrupt request using the SID and SQ fields in the
    /// IRTE.
    RequesterId = 0b01,
    /// Verify the most significant 8 bits of the requester-id (Bus#) in the interrupt
    /// request are equal to or within the Startbus# and EndBus# specified through the
    /// upper and lower 8 bits of the SID field respectively.
    RequesterBus = 0b10,
    Reserved = 0b11,
}

/// Source ID qualifier. This field is evaluated by hardware only when the Present bit
/// is Set and the SVT field is 0b01.
#[derive(Debug, TryFromInt)]
#[repr(u32)]
pub enum SourceIdQualifier {
    /// Verify the interrupt request by comparing all 16 bits of the SID field with the
    /// 16-bit requester-id of the interrupt request.
    All = 0b00,
    /// Verify the interrupt request by comparing the **most significant 13 bits** of the
    /// SID and requester-id of the interrupt request, and comparing the **least significant
    /// two bits** of the SID field and requester-id of the interrupt request.
    IgnoreThirdLeast = 0b01,
    /// Verify the interrupt request by comparing the **most significant 13 bits** of the
    /// SID and requester-id of the interrupt request, and comparing the **least significant
    /// bit** of the SID field and requester-id of the interrupt request.
    IgnoreSecondThirdLeast = 0b10,
    /// Verify the interrupt request by comparing the **most significant 13 bits** of the
    /// SID and requester-id of the interrupt request.
    IgnoreLeastThree = 0b11,
}

#[derive(Debug, TryFromInt)]
#[repr(u32)]
enum DeliveryMode {
    FixedMode = 0b000,
    LowestPriority = 0b001,
    SystemManagementInterrupt = 0b010,
    NonMaskableInterrupt = 0b100,
    Init = 0b101,
    ExInt = 0b111,
}

/// Interrupt Remapping Table Entry (IRTE) for Remapped Interrupts.
pub struct IrtEntry(u128);

impl IrtEntry {
    /// Creates an enabled entry with no validation,
    ///
    /// DST = 0, IM = 0, DLM = 0, TM = 0, RH = 0, DM = 0, FPD = 1, P = 1
    pub(super) fn new_enabled(vector: u32) -> Self {
        Self(0b11 | ((vector as u128) << 16))
    }

    fn as_raw_u64(&self) -> [u64; 2] {
        [self.0 as u64, (self.0 >> 64) as u64]
    }

    pub fn source_validation_type(&self) -> SourceValidationType {
        const SVT_MASK: u128 = 0x3 << 82;
        SourceValidationType::try_from(((self.0 & SVT_MASK) >> 82) as u32).unwrap()
    }

    pub fn source_id_qualifier(&self) -> SourceIdQualifier {
        const SQ_MASK: u128 = 0x3 << 82;
        SourceIdQualifier::try_from(((self.0 & SQ_MASK) >> 82) as u32).unwrap()
    }

    pub const fn source_identifier(&self) -> u32 {
        const SID_MASK: u128 = 0xFFFF << 64;
        ((self.0 & SID_MASK) >> 64) as u32
    }

    /// This field identifies the remapped interrupt request’s target processor(s). It is
    /// evaluated by hardware only when the Present (P) field is Set.
    ///
    /// The format of this field in various Interrupt Remapping modes is as follows:
    /// - Intel xAPIC Mode (IRTA_REG.EIME=0):
    ///     - 63:48 - Reserved (0)
    ///     - 47:40 - APIC DestinationID\[7:0\]
    ///     - 39:32 - Reserved (0)
    /// - Intel x2APIC Mode (IRTA_REG.EIME=1):
    ///     - 63:32 - APIC DestinationID\[31:0\]
    pub const fn destination_id(&self) -> u32 {
        const DST_MASK: u128 = 0xFFFF_FFFF << 32;
        ((self.0 & DST_MASK) >> 32) as u32
    }

    pub const fn vector(&self) -> u8 {
        const VECTOR_MASK: u128 = 0xFF << 16;
        ((self.0 & VECTOR_MASK) >> 16) as u8
    }

    pub const fn flags(&self) -> IrtEntryFlags {
        IrtEntryFlags::from_bits_truncate((self.0 & 0xFFFF_FFFF) as u32)
    }
}

impl Debug for IrtEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrtEntry")
            .field("flags", &self.flags())
            .field("destination_id", &self.destination_id())
            .field("vector", &self.vector())
            .field("source_identifier", &self.source_identifier())
            .field("source_id_qualifier", &self.source_id_qualifier())
            .field("source_validation_type", &self.source_validation_type())
            .field("raw", &self.0)
            .finish()
    }
}

bitflags! {
    /// Interrupt Remapping Table Entry Flags for Remapped Interrupts.
    pub struct IrtEntryFlags: u32{
        /// Present bit
        const P =           1 << 0;
        /// Fault Processing Disable. Enables or disables recording/reporting of faults
        /// caused by interrupt messages requests processed through this entry.
        ///
        /// - 0: Enabled
        /// - 1: Disabled
        const FPD =         1 << 1;
        /// Destination Mode, indicates the Destination ID in an IRTE should be interpreted
        /// as logical or physical APIC ID.
        ///
        /// - 0: Physical
        /// - 1: Logical
        const DM =          1 << 2;
        /// Redirection Hint, indicates whether the remapped interrupt request should be
        /// directed to one among N processors specified in Destination ID.
        ///
        /// - 0: The remapped interrupt is directed to the processor.
        /// - 1: The remapped interrupt is directed to 1 of N processors.
        const RH =          1 << 3;
        /// Trigger Mode.
        ///
        /// - 0: Edge sensitive
        /// - 1: Level sensitive
        const TM =          1 << 4;
        /// IRTE Mode.
        ///
        /// - 0: Remapped Mode.
        /// - 1: Posted Mode.
        const IM =          1 << 15;
    }
}
