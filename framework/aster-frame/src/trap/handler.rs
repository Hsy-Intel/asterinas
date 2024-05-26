// SPDX-License-Identifier: MPL-2.0

#[cfg(feature = "intel_tdx")]
use crate::arch::tdx_guest::{handle_virtual_exception, TdxTrapFrame};
use crate::early_println;
use crate::{
    arch::{
        irq::IRQ_LIST,
        mm::{is_kernel_vaddr, PageTableEntry, PageTableFlags, ALL_MAPPED_PTE},
    },
    boot::memory_region::MemoryRegion,
    config::PHYS_OFFSET,
    cpu::{CpuException, PageFaultErrorCode, PAGE_FAULT},
    cpu_local,
    user::UserMode,
    vm::{
        page_table::{table_of, PageTableEntryTrait, PageTableFlagsTrait, KERNEL_PAGE_TABLE},
        PageTable,
    },
};
#[cfg(feature = "intel_tdx")]
use tdx_guest::tdcall;
use trapframe::TrapFrame;

#[cfg(feature = "intel_tdx")]
impl TdxTrapFrame for TrapFrame {
    fn rax(&self) -> usize {
        self.rax
    }
    fn set_rax(&mut self, rax: usize) {
        self.rax = rax;
    }
    fn rbx(&self) -> usize {
        self.rbx
    }
    fn set_rbx(&mut self, rbx: usize) {
        self.rbx = rbx;
    }
    fn rcx(&self) -> usize {
        self.rcx
    }
    fn set_rcx(&mut self, rcx: usize) {
        self.rcx = rcx;
    }
    fn rdx(&self) -> usize {
        self.rdx
    }
    fn set_rdx(&mut self, rdx: usize) {
        self.rdx = rdx;
    }
    fn rsi(&self) -> usize {
        self.rsi
    }
    fn set_rsi(&mut self, rsi: usize) {
        self.rsi = rsi;
    }
    fn rdi(&self) -> usize {
        self.rdi
    }
    fn set_rdi(&mut self, rdi: usize) {
        self.rdi = rdi;
    }
    fn rip(&self) -> usize {
        self.rip
    }
    fn set_rip(&mut self, rip: usize) {
        self.rip = rip;
    }
    fn r8(&self) -> usize {
        self.r8
    }
    fn set_r8(&mut self, r8: usize) {
        self.r8 = r8;
    }
    fn r9(&self) -> usize {
        self.r9
    }
    fn set_r9(&mut self, r9: usize) {
        self.r9 = r9;
    }
    fn r10(&self) -> usize {
        self.r10
    }
    fn set_r10(&mut self, r10: usize) {
        self.r10 = r10;
    }
    fn r11(&self) -> usize {
        self.r11
    }
    fn set_r11(&mut self, r11: usize) {
        self.r11 = r11;
    }
    fn r12(&self) -> usize {
        self.r12
    }
    fn set_r12(&mut self, r12: usize) {
        self.r12 = r12;
    }
    fn r13(&self) -> usize {
        self.r13
    }
    fn set_r13(&mut self, r13: usize) {
        self.r13 = r13;
    }
    fn r14(&self) -> usize {
        self.r14
    }
    fn set_r14(&mut self, r14: usize) {
        self.r14 = r14;
    }
    fn r15(&self) -> usize {
        self.r15
    }
    fn set_r15(&mut self, r15: usize) {
        self.r15 = r15;
    }
    fn rbp(&self) -> usize {
        self.rbp
    }
    fn set_rbp(&mut self, rbp: usize) {
        self.rbp = rbp;
    }
}

/// Only from kernel
#[no_mangle]
extern "sysv64" fn trap_handler(f: &mut TrapFrame) {
    if CpuException::is_cpu_exception(f.trap_num as u16) {
        #[cfg(feature = "intel_tdx")]
        if f.trap_num as u16 == 20 {
            let ve_info = tdcall::get_veinfo().expect("#VE handler: fail to get VE info\n");
            handle_virtual_exception(f, &ve_info);
            return;
        }
        if f.trap_num as u16 == PAGE_FAULT.number {
            kernel_page_fault_handler(f);
            return;
        }
        panic!("cannot handle kernel cpu fault now, information:{:#x?}", f);
    } else {
        call_irq_callback_functions(f);
    }
}

pub(crate) fn call_irq_callback_functions(trap_frame: &TrapFrame) {
    let irq_line = IRQ_LIST.get().unwrap().get(trap_frame.trap_num).unwrap();
    let callback_functions = irq_line.callback_list();
    for callback_function in callback_functions.iter() {
        callback_function.call(trap_frame);
    }
    if !CpuException::is_cpu_exception(trap_frame.trap_num as u16) {
        crate::arch::interrupts_ack();
    }
}

fn kernel_page_fault_handler(f: &TrapFrame) {
    // We only create mapping: `vaddr = paddr + PHYS_OFFSET` in kernel page fault handler.
    let page_fault_vaddr = x86_64::registers::control::Cr2::read().as_u64();
    debug_assert!(is_kernel_vaddr(page_fault_vaddr as usize));

    // Check kernel region
    // FIXME: The modification to the offset mapping of the kernel code and data should not permitted.
    let kernel_region = MemoryRegion::kernel();
    debug_assert!(
        page_fault_vaddr < kernel_region.base() as u64
            || page_fault_vaddr > (kernel_region.base() + kernel_region.len()) as u64
    );

    // Check error code and construct flags
    let error_code = PageFaultErrorCode::from_bits_truncate(f.error_code);
    debug_assert!(!error_code.contains(PageFaultErrorCode::USER));
    // Instruction fetch is not permitted in kernel page fault handler
    debug_assert!(!error_code.contains(PageFaultErrorCode::INSTRUCTION));
    let mut flags = PageTableFlags::empty()
        .set_present(true)
        .set_executable(false)
        | PageTableFlags::SHARED;
    if error_code.contains(PageFaultErrorCode::WRITE) {
        flags = flags.set_writable(true);
    }

    // Handle page fault
    let mut kernel_page_table = KERNEL_PAGE_TABLE.get().unwrap().lock_irq_disabled();
    if error_code.contains(PageFaultErrorCode::PRESENT) {
        // Safety: The page fault address has been checked and the flags is constructed based on error code.
        unsafe {
            kernel_page_table
                .protect(page_fault_vaddr as usize, flags)
                .unwrap();
        }
    } else {
        // Safety: The page fault address has been checked and the flags is constructed based on error code.
        let paddr = page_fault_vaddr as usize - PHYS_OFFSET;
        unsafe {
            kernel_page_table
                .map(page_fault_vaddr as usize, paddr, flags)
                .unwrap();
        }
        // Safety: page_directory_base is read from kernel page table, the address is valid.
        let p4 = unsafe { table_of::<PageTableEntry>(kernel_page_table.root_paddr()).unwrap() };
        let mut map_pte = ALL_MAPPED_PTE.lock();
        let pte_entry_index = PageTableEntry::page_index(page_fault_vaddr as usize, 4);
        if !map_pte.contains_key(&pte_entry_index) {
            map_pte.insert(pte_entry_index, p4[pte_entry_index]);
        }

        // Although the mapping is constructed in the kernel page table, there are still some cases where the mapping is
        // not added to the current page table (such as the user mode page table created).
        //
        // Safety: The modification will not affect kernel safety and the virtual address doesn't belong to the user
        // virtual address.
        unsafe {
            let mut current_page_table: PageTable<PageTableEntry, crate::vm::page_table::UserMode> =
                PageTable::from_root_register();
            current_page_table.add_root_mapping(pte_entry_index, &p4[pte_entry_index]);
        }
    }
}
