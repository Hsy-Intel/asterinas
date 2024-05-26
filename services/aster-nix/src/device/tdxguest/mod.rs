// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::{
    error::Error,
    events::IoEvents,
    fs::{inode_handle::FileIo, utils::IoctlCmd},
    process::signal::Poller,
    util::{read_bytes_from_user, read_val_from_user, write_bytes_to_user, write_val_to_user},
};

use alloc::vec;
use aster_frame::config::PAGE_SIZE;
use aster_frame::sync::WaitQueue;
use aster_frame::vm::{vaddr_to_paddr, DmaCoherent, HasPaddr, VmAllocOptions, VmIo};
// use aster_frame::vm::DmaDirection;
use tdx_guest::tdcall::{get_report, extend_rtmr, TdCallError};
use tdx_guest::tdvmcall::{get_quote, setup_event_notify_interrupt, TdVmcallError};
use tdx_guest::SHARED_MASK;


const TDX_REPORTDATA_LEN: usize = 64;
const TDX_REPORT_LEN: usize = 1024;
const TDX_EXTEND_RTMR_DATA_LEN: usize = 48;

#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
struct TdxReportReq {
    reportdata: [u8; TDX_REPORTDATA_LEN],
    tdreport: [u8; TDX_REPORT_LEN],
}

#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
struct TdxQuoteReq {
    buf: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
struct TdxExtendRtmrReq {
	data: [u8; TDX_EXTEND_RTMR_DATA_LEN],
	index: u8,
}

#[repr(align(64))]
#[repr(C)]
struct ReportDataWapper {
    report_data: [u8; TDX_REPORTDATA_LEN],
}

#[repr(align(1024))]
#[repr(C)]
struct TdxReportWapper {
    tdx_report: [u8; TDX_REPORT_LEN],
}

#[repr(align(64))]
#[repr(C)]
struct ExtendRtmrWapper {
    data: [u8; TDX_EXTEND_RTMR_DATA_LEN],
	index: u8,
}

struct QuoteEntry {
    // Kernel buffer to share data with VMM (size is page aligned)
    buf: DmaCoherent,
    // Size of the allocated memory
    buf_len: usize,
    // completion: GetQuoteCompletion,
    // Support parallel GetQuote requests

}

#[repr(C)]
struct TdxQuoteHdr {
    // Quote version, filled by TD
    version: u64,
    // Status code of Quote request, filled by VMM
    status: u64,
    // Length of TDREPORT, filled by TD
    in_len: u32,
    // Length of Quote, filled by VMM
    out_len: u32,
    // Actual Quote data or TDREPORT on input
    data: Vec<u64>,
}

// pub struct GetQuoteCompletion {
//     completion: AtomicBool,
//     queue: WaitQueue,
// }

// list: Vec<usize>,

// impl GetQuoteCompletion {
//     /// Create a new completion object.
//     pub fn new() -> Self {
//         Self {
//             completion: AtomicBool::new(false),
//             queue: WaitQueue::new(),
//         }
//     }

//     /// Wait for the completion to be completed.
//     pub fn wait(&self) {
//         // Wait until the `done` flag is set to true.
//         self.queue.wait_until(|| self.completion.load(Ordering::Acquire));
//     }

//     /// Complete the task and wake up all waiting threads.
//     pub fn complete(&self) {
//         // Set the `done` flag to true.
//         self.completion.store(true, Ordering::Release);
//         // Wake up all threads in the wait queue.
//         self.queue.wake_all();
//     }
// }

pub struct TdxGuest;

impl Device for TdxGuest {
    fn type_(&self) -> DeviceType {
        DeviceType::MiscDevice
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(0xa, 0x7b)
    }
}

impl From<TdCallError> for Error {
    fn from(err: TdCallError) -> Self {
        match err {
            TdCallError::TdxNoValidVeInfo => {
                Error::with_message(Errno::EINVAL, "TdCallError::TdxNoValidVeInfo")
            }
            TdCallError::TdxOperandInvalid => {
                Error::with_message(Errno::EINVAL, "TdCallError::TdxOperandInvalid")
            }
            TdCallError::TdxPageAlreadyAccepted => {
                Error::with_message(Errno::EINVAL, "TdCallError::TdxPageAlreadyAccepted")
            }
            TdCallError::TdxPageSizeMismatch => {
                Error::with_message(Errno::EINVAL, "TdCallError::TdxPageSizeMismatch")
            }
            TdCallError::TdxOperandBusy => {
                Error::with_message(Errno::EBUSY, "TdCallError::TdxOperandBusy")
            }
            TdCallError::Other => Error::with_message(Errno::EAGAIN, "TdCallError::Other"),
        }
    }
}

impl From<TdVmcallError> for Error {
    fn from(err: TdVmcallError) -> Self {
        match err {
            TdVmcallError::TdxRetry => {
                Error::with_message(Errno::EINVAL, "TdVmcallError::TdxRetry")
            }
            TdVmcallError::TdxOperandInvalid => {
                Error::with_message(Errno::EINVAL, "TdVmcallError::TdxOperandInvalid")
            }
            TdVmcallError::TdxGpaInuse => {
                Error::with_message(Errno::EINVAL, "TdVmcallError::TdxGpaInuse")
            }
            TdVmcallError::TdxAlignError => {
                Error::with_message(Errno::EINVAL, "TdVmcallError::TdxAlignError")
            }
            TdVmcallError::Other => Error::with_message(Errno::EAGAIN, "TdVmcallError::Other"),
        }
    }
}

impl FileIo for TdxGuest {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        return_errno_with_message!(Errno::EPERM, "Read operation not supported")
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        return_errno_with_message!(Errno::EPERM, "Write operation not supported")
    }

    fn ioctl(&self, cmd: IoctlCmd, arg: usize) -> Result<i32> {
        match cmd {
            IoctlCmd::TDXGETREPORT => handle_get_report(arg),
            IoctlCmd::TDXGETQUOTE => handle_get_quote(arg),
            IoctlCmd::TDXEXTENDRTMR => handle_extend_rtmr(arg),
            _ => return_errno_with_message!(Errno::EPERM, "Unsupported ioctl"),
        }
    }

    fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

fn handle_get_report(arg: usize) -> Result<i32> {
    let tdx_report: TdxReportReq = read_val_from_user(arg)?;
    let wrapped_report = TdxReportWapper {
        tdx_report: tdx_report.tdreport,
    };
    let wrapped_data = ReportDataWapper {
        report_data: tdx_report.reportdata,
    };
    if let Err(err) = get_report(
        vaddr_to_paddr(wrapped_report.tdx_report.as_ptr() as usize).unwrap() as u64,
        vaddr_to_paddr(wrapped_data.report_data.as_ptr() as usize).unwrap() as u64,
    ) {
        println!("[kernel]: get TDX report error");
        return Err(err.into());
    }
    let tdx_report_vaddr = arg + TDX_REPORTDATA_LEN;
    write_bytes_to_user(tdx_report_vaddr, &wrapped_report.tdx_report)?;
    Ok(0)
}

fn handle_get_quote(arg: usize) -> Result<i32> {
    const GET_QUOTE_IN_FLIGHT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    let tdx_quote: TdxQuoteReq = read_val_from_user(arg)?;
    if tdx_quote.len == 0 {
        return Err(Error::with_message(Errno::EINVAL, "Invalid parameter"));
    }
    let entry = alloc_quote_entry(tdx_quote.len);

    // Copy data (with TDREPORT) from user buffer to kernel Quote buffer
    let mut quote_buffer = vec![0u8; entry.buf_len];
    read_bytes_from_user(tdx_quote.buf, &mut quote_buffer)?;
    entry.buf.write_bytes(0, &quote_buffer)?;

    if let Err(err) = get_quote(
        (entry.buf.paddr() as u64) | SHARED_MASK,
        entry.buf_len as u64,
    ) {
        println!("[kernel] get quote error: {:?}", err);
        return Err(err.into());
    }

    // completion.wait();
    // Poll for the quote to be ready.
    loop {
        entry.buf.read_bytes(0, &mut quote_buffer)?;
        let quote_hdr: TdxQuoteHdr = parse_quote_header(&quote_buffer);
        if quote_hdr.status != GET_QUOTE_IN_FLIGHT {
            break;
        }
    };
    entry.buf.read_bytes(0, &mut quote_buffer)?;
    write_bytes_to_user(tdx_quote.buf, &mut quote_buffer)?;
    Ok(0)
}

fn handle_extend_rtmr(arg: usize) -> Result<i32> {
    let extend_rtmr_req: TdxExtendRtmrReq = read_val_from_user(arg)?;
    if extend_rtmr_req.index < 2 {
        return Err(Error::with_message(Errno::EINVAL, "Invalid parameter"));
    }
    let wrapped_extend_rtmr = ExtendRtmrWapper {
        data: extend_rtmr_req.data,
        index: extend_rtmr_req.index,
    };
    if let Err(err) = extend_rtmr(
        vaddr_to_paddr(wrapped_extend_rtmr.data.as_ptr() as usize).unwrap() as u64,
        wrapped_extend_rtmr.index as u64,
    ) {
        println!("[kernel]: TDX extend rtmr error");
        return Err(err.into());
    }
    Ok(0)
}

fn alloc_quote_entry(buf_len: usize) -> QuoteEntry {
    const PAGE_MASK: usize = PAGE_SIZE - 1;
    let aligned_buf_len = buf_len & (!PAGE_MASK);
    // Cause `ls` hangs.
    let dma_buf: DmaCoherent = DmaCoherent::map(
        VmAllocOptions::new(aligned_buf_len / (PAGE_SIZE))
            .is_contiguous(true)
            .alloc_contiguous()
            .unwrap(),
        true,
    )
    .unwrap();
    let entry = QuoteEntry {
        buf: dma_buf,
        buf_len: aligned_buf_len as usize,
        // completion: GetQuoteCompletion::new(),
    };
    entry
}

fn parse_quote_header(buffer: &[u8]) -> TdxQuoteHdr {
    let version = u64::from_be_bytes(buffer[0..8].try_into().unwrap());
    let status = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
    let in_len = u32::from_be_bytes(buffer[16..20].try_into().unwrap());
    let out_len = u32::from_be_bytes(buffer[20..24].try_into().unwrap());

    TdxQuoteHdr {
        version,
        status,
        in_len,
        out_len,
        data: vec![0],
    }
}

// fn quote_callback_handler(struct work_struct *work) {
//        struct tdx_quote_hdr *quote_hdr;
//        struct quote_entry *entry, *next;

//        /* Find processed quote request and mark it complete */
//        mutex_lock(&quote_lock);
//        list_for_each_entry_safe(entry, next, &quote_list, list) {
//                quote_hdr = (struct tdx_quote_hdr *)entry->buf;
//                if (quote_hdr->status == GET_QUOTE_IN_FLIGHT)
//                        continue;
//                /*
//                 * If user invalidated the current request, remove the
//                 * entry from the quote list and free it. If the request
//                 * is still valid, mark it complete.
//                 */
//                if (entry->valid)
//                        complete(&entry->compl);
//                else
//                        _del_quote_entry(entry);
//        }
//        mutex_unlock(&quote_lock);
// }

// static int tdx_guest_probe(struct platform_device *pdev)
// {
//        quote_wq = create_singlethread_workqueue("tdx_quote_handler");

//        INIT_WORK(&quote_work, quote_callback_handler);

//        /*
//         * Register event notification IRQ to get Quote completion
//         * notification. Since tdx_notify_irq is not specific to the
//         * attestation feature, use IRQF_SHARED to make it shared IRQ.
//         * Use IRQF_NOBALANCING to make sure the IRQ affinity will not
//         * be changed.
//         */
//        if (request_irq(tdx_notify_irq, attestation_callback_handler,
//                                IRQF_NOBALANCING | IRQF_SHARED,
//                                "tdx_quote_irq", &tdx_misc_dev)) {
//                pr_err("notify IRQ request failed\n");
//                destroy_workqueue(quote_wq);
//                return -EIO;
//        }

//        return misc_register(&tdx_misc_dev);
// }

// use aster_frame::trap::IrqLine;
// fn tdx_dev_init() {
//     // Create a workqueue for handling Quote completion notification.
//     let tdx_event_irq = IrqLine::alloc().unwrap();
//     setup_event_notify_interrupt(tdx_event_irq);
//     // Register event notification IRQ to get Quote completion notification.
//     tdx_event_irq.on_active(quote_callback_handler);
// }
