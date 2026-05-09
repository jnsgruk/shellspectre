/// Byte offsets resolved from kernel BTF at runtime, shared with eBPF
/// via an array map. These allow reading `ppid`, `euid`, and `tty_nr`
/// from `task_struct` without hardcoding kernel-version-specific offsets.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskFieldOffsets {
    /// Offset of `real_parent` (ptr) in `task_struct`.
    pub task_real_parent: u64,
    /// Offset of `tgid` (pid_t) in `task_struct`.
    pub task_tgid: u64,
    /// Offset of `cred` (ptr) in `task_struct`.
    pub task_cred: u64,
    /// Offset of `euid` (kuid_t) in `cred`.
    pub cred_euid: u64,
    /// Offset of `signal` (ptr) in `task_struct`.
    pub task_signal: u64,
    /// Offset of `tty` (ptr) in `signal_struct`.
    pub signal_tty: u64,
    /// Offset of `index` (int) in `tty_struct`.
    pub tty_index: u64,
    /// Offset of `files` (ptr) in `task_struct`.
    pub task_files: u64,
    /// Offset of `fdt` (ptr) in `files_struct`.
    pub files_fdt: u64,
    /// Offset of `fd` (ptr) in `fdtable`.
    pub fdt_fd: u64,
    /// Offset of `f_inode` (ptr) in `file`.
    pub file_inode: u64,
    /// Offset of `i_rdev` (dev_t) in `inode`.
    pub inode_rdev: u64,
}

impl TaskFieldOffsets {
    /// Return all offsets as an array indexed by [`offset_idx`] constants.
    ///
    /// This is the single source of truth for the mapping between struct
    /// fields and BPF array map indices.
    pub const fn as_array(&self) -> [u64; offset_idx::COUNT as usize] {
        [
            self.task_real_parent,
            self.task_tgid,
            self.task_cred,
            self.cred_euid,
            self.task_signal,
            self.signal_tty,
            self.tty_index,
            self.task_files,
            self.files_fdt,
            self.fdt_fd,
            self.file_inode,
            self.inode_rdev,
        ]
    }
}

/// Array map indices for [`TaskFieldOffsets`] fields, used with a
/// `BPF_MAP_TYPE_ARRAY` of `u64` values.
pub mod offset_idx {
    pub const TASK_REAL_PARENT: u32 = 0;
    pub const TASK_TGID: u32 = 1;
    pub const TASK_CRED: u32 = 2;
    pub const CRED_EUID: u32 = 3;
    pub const TASK_SIGNAL: u32 = 4;
    pub const SIGNAL_TTY: u32 = 5;
    pub const TTY_INDEX: u32 = 6;
    pub const TASK_FILES: u32 = 7;
    pub const FILES_FDT: u32 = 8;
    pub const FDT_FD: u32 = 9;
    pub const FILE_INODE: u32 = 10;
    pub const INODE_RDEV: u32 = 11;
    pub const COUNT: u32 = 12;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn task_field_offsets_array_length_matches_count() {
        let offsets = TaskFieldOffsets {
            task_real_parent: 10,
            task_tgid: 20,
            task_cred: 30,
            cred_euid: 40,
            task_signal: 50,
            signal_tty: 60,
            tty_index: 70,
            task_files: 80,
            files_fdt: 90,
            fdt_fd: 100,
            file_inode: 110,
            inode_rdev: 120,
        };
        let arr = offsets.as_array();
        assert_eq!(arr.len(), offset_idx::COUNT as usize);
        assert_eq!(arr[offset_idx::TASK_REAL_PARENT as usize], 10);
        assert_eq!(arr[offset_idx::TASK_TGID as usize], 20);
        assert_eq!(arr[offset_idx::TASK_CRED as usize], 30);
        assert_eq!(arr[offset_idx::CRED_EUID as usize], 40);
        assert_eq!(arr[offset_idx::TASK_SIGNAL as usize], 50);
        assert_eq!(arr[offset_idx::SIGNAL_TTY as usize], 60);
        assert_eq!(arr[offset_idx::TTY_INDEX as usize], 70);
        assert_eq!(arr[offset_idx::TASK_FILES as usize], 80);
        assert_eq!(arr[offset_idx::FILES_FDT as usize], 90);
        assert_eq!(arr[offset_idx::FDT_FD as usize], 100);
        assert_eq!(arr[offset_idx::FILE_INODE as usize], 110);
        assert_eq!(arr[offset_idx::INODE_RDEV as usize], 120);
    }

    #[test]
    fn task_field_offsets_size() {
        assert_eq!(mem::size_of::<TaskFieldOffsets>(), 96);
    }
}
