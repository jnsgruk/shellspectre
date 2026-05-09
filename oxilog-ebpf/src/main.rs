#![no_std]
#![no_main]
#![allow(deprecated)] // bpf_probe_read_user_str is simpler for fixed-size buffers

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_task, bpf_ktime_get_ns,
};
use oxilog_common::{EventHeader, EventType, ExecEvent, MAX_ARGV_COUNT, offset_idx};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Pending exec events keyed by pid_tgid, filled on sys_enter_execve
/// and consumed on sys_exit_execve.
#[map]
static PENDING_EXEC: HashMap<u64, ExecEvent> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch space for building an [`ExecEvent`] without
/// exceeding the 512-byte BPF stack limit.
#[map]
static EXEC_SCRATCH: aya_ebpf::maps::PerCpuArray<ExecEvent> =
    aya_ebpf::maps::PerCpuArray::with_max_entries(1, 0);

/// Single-element array map populated by userspace with BTF-resolved offsets.
#[map]
static OFFSETS: Array<u64> = Array::with_max_entries(offset_idx::COUNT, 0);

/// Read a u64 offset value from the OFFSETS map.
fn get_offset(idx: u32) -> u64 {
    OFFSETS.get(idx).copied().unwrap_or(0)
}

/// Read a pointer-sized value from a kernel address at a given byte offset.
///
/// # Safety
///
/// `base` must be a valid kernel pointer and `offset` must point to a
/// pointer-sized field within the object.
unsafe fn read_ptr(base: u64, offset: u64) -> Result<u64, i64> {
    let addr = (base + offset) as *const u64;
    // SAFETY: caller guarantees base+offset points to a valid kernel pointer field.
    unsafe { bpf_probe_read_kernel(addr) }
}

/// Read a u32 value from a kernel address at a given byte offset.
///
/// # Safety
///
/// `base` must be a valid kernel pointer and `offset` must point to a
/// u32-sized field within the object.
unsafe fn read_u32(base: u64, offset: u64) -> Result<u32, i64> {
    let addr = (base + offset) as *const u32;
    // SAFETY: caller guarantees base+offset points to a valid kernel u32 field.
    unsafe { bpf_probe_read_kernel(addr) }
}

/// Populate common event header fields from current task context.
#[allow(clippy::similar_names)]
fn fill_header(event_type: EventType) -> EventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: bpf_get_current_task returns a pointer to the current task_struct.
    let task = unsafe { bpf_get_current_task() };

    let ppid = read_ppid(task);
    let euid = read_euid(task);
    let tty_nr = read_tty_nr(task);

    EventHeader::new(
        event_type,
        // SAFETY: bpf_ktime_get_ns has no preconditions.
        unsafe { bpf_ktime_get_ns() },
        pid,
        ppid,
        pid_tgid as u32,
        pid,
        uid_gid as u32,
        (uid_gid >> 32) as u32,
        euid,
        bpf_get_current_comm().unwrap_or([0u8; 16]),
        tty_nr,
        // SAFETY: bpf_get_current_cgroup_id has no preconditions.
        unsafe { bpf_get_current_cgroup_id() },
    )
}

/// Read ppid by following task->real_parent->tgid.
fn read_ppid(task: u64) -> u32 {
    // SAFETY: task is from bpf_get_current_task, offsets are BTF-resolved.
    unsafe {
        let Ok(parent) = read_ptr(task, get_offset(offset_idx::TASK_REAL_PARENT)) else {
            return 0;
        };
        read_u32(parent, get_offset(offset_idx::TASK_TGID)).unwrap_or(0)
    }
}

/// Read euid by following task->cred->euid.val.
fn read_euid(task: u64) -> u32 {
    // SAFETY: task is from bpf_get_current_task, offsets are BTF-resolved.
    unsafe {
        let Ok(cred) = read_ptr(task, get_offset(offset_idx::TASK_CRED)) else {
            return 0;
        };
        read_u32(cred, get_offset(offset_idx::CRED_EUID)).unwrap_or(0)
    }
}

/// Read tty index by following task->signal->tty->index.
/// Returns 0 if any pointer in the chain is null (no controlling tty).
fn read_tty_nr(task: u64) -> u32 {
    // SAFETY: task is from bpf_get_current_task, offsets are BTF-resolved.
    unsafe {
        let Ok(signal) = read_ptr(task, get_offset(offset_idx::TASK_SIGNAL)) else {
            return 0;
        };
        let Ok(tty) = read_ptr(signal, get_offset(offset_idx::SIGNAL_TTY)) else {
            return 0;
        };
        if tty == 0 {
            return 0;
        }
        read_u32(tty, get_offset(offset_idx::TTY_INDEX)).unwrap_or(0)
    }
}

#[allow(clippy::needless_pass_by_value)] // aya macro requires owned TracePointContext
#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[allow(clippy::similar_names)]
fn try_sys_enter_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // ExecEvent is ~5.5KB — too large for the 512-byte BPF stack.
    // Use a per-CPU array as scratch space to build the event.
    let Some(scratch) = EXEC_SCRATCH.get_ptr_mut(0) else {
        return Err(1);
    };

    // SAFETY: scratch points to per-CPU array entry; we write each field
    // individually to stay within BPF stack limits.
    unsafe {
        let hdr = fill_header(EventType::Exec);
        core::ptr::write(&raw mut (*scratch).header, hdr);
        core::ptr::write(&raw mut (*scratch).retval, 0);

        // Read filename pointer from tracepoint args (offset 16).
        let Ok(filename_ptr): Result<*const u8, _> = ctx.read_at(16) else {
            return Err(1);
        };
        let filename = &raw mut (*scratch).filename;
        (*filename).fill(0);
        let _ = aya_ebpf::helpers::bpf_probe_read_user_str(filename_ptr, &mut *filename);

        // Read argv pointer from tracepoint args (offset 24).
        let Ok(argv_base): Result<*const *const u8, _> = ctx.read_at(24) else {
            return Err(1);
        };

        // Zero the argv array first.
        let argv = &raw mut (*scratch).argv;
        core::ptr::write_bytes(argv.cast::<u8>(), 0, core::mem::size_of_val(&*argv));

        let mut count: u32 = 0;
        for i in 0..MAX_ARGV_COUNT {
            let Ok(arg_ptr) = aya_ebpf::helpers::bpf_probe_read_user(argv_base.add(i)) else {
                break;
            };
            if arg_ptr.is_null() {
                break;
            }
            let dest = &raw mut (*argv)[i];
            let _ = aya_ebpf::helpers::bpf_probe_read_user_str(arg_ptr, &mut *dest);
            count += 1;
        }

        core::ptr::write(&raw mut (*scratch).argc, count);

        // Stash in hash map for sys_exit_execve to pick up.
        let _ = PENDING_EXEC.insert(&pid_tgid, &*scratch, 0);
    }

    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // aya macro requires owned TracePointContext
#[tracepoint]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    match try_sys_exit_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_sys_exit_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: retval is at offset 16 in sys_exit_execve tracepoint args.
    let retval: i64 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    // Look up the pending exec event stashed by sys_enter_execve.
    // SAFETY: PENDING_EXEC is a valid BPF hash map and pid_tgid is a valid key.
    let Some(pending) = (unsafe { PENDING_EXEC.get(&pid_tgid) }) else {
        return Err(1);
    };

    // Reserve ring buffer space and copy the pending event with retval set.
    let mut entry = EVENTS.reserve::<ExecEvent>(0).ok_or(1i64)?;
    let event = entry.as_mut_ptr();

    // SAFETY: pending points to valid hash map entry, event to reserved ringbuf memory.
    unsafe {
        core::ptr::copy_nonoverlapping(pending, event, 1);
        core::ptr::write(&raw mut (*event).retval, retval);
    }

    entry.submit(0);

    // Clean up the pending entry.
    let _ = PENDING_EXEC.remove(&pid_tgid);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
