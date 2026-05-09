//! Minimal BTF parser for resolving struct field byte offsets from the kernel's
//! `/sys/kernel/btf/vmlinux`. Only supports `BTF_KIND_STRUCT` member lookups —
//! just enough to read `task_struct`, `cred`, `signal_struct`, and `tty_struct`
//! field positions at runtime.

use anyhow::{Context, Result, bail};
use oxilog_common::TaskFieldOffsets;
use std::fs;

// BTF format constants (from include/uapi/linux/btf.h).
const BTF_MAGIC: u16 = 0xEB9F;
const BTF_KIND_STRUCT: u32 = 4;

/// Parsed BTF data with references into the raw byte buffer.
struct Btf {
    data: Vec<u8>,
    hdr_len: usize,
    type_off: usize,
    type_len: usize,
    str_off: usize,
}

impl Btf {
    fn from_sys_fs() -> Result<Self> {
        let data = fs::read("/sys/kernel/btf/vmlinux").context("failed to read kernel BTF")?;

        if data.len() < 24 {
            bail!("BTF data too short");
        }
        let magic = u16::from_ne_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            bail!("bad BTF magic: {magic:#x}");
        }

        let hdr_len = u32::from_ne_bytes(data[4..8].try_into()?) as usize;
        let type_off = u32::from_ne_bytes(data[8..12].try_into()?) as usize;
        let type_len = u32::from_ne_bytes(data[12..16].try_into()?) as usize;
        let str_off = u32::from_ne_bytes(data[16..20].try_into()?) as usize;

        Ok(Self {
            data,
            hdr_len,
            type_off,
            type_len,
            str_off,
        })
    }

    /// Look up a null-terminated string from the BTF string table.
    fn string(&self, offset: u32) -> &str {
        let start = self.hdr_len + self.str_off + offset as usize;
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.data.len(), |p| start + p);
        std::str::from_utf8(&self.data[start..end]).unwrap_or("")
    }

    fn read_u32(&self, off: usize) -> u32 {
        u32::from_ne_bytes(
            self.data
                .get(off..off + 4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or_default(),
        )
    }

    /// Compute extra bytes after the 12-byte type header for a given BTF kind.
    fn extra_bytes(kind: u32, vlen: usize) -> usize {
        // BTF kinds: 0=UNKN 1=INT 2=PTR 3=ARRAY 4=STRUCT 5=UNION
        // 6=ENUM 7=FWD 8=TYPEDEF 9=VOLATILE 10=CONST 11=RESTRICT
        // 12=FUNC 13=FUNC_PROTO 14=VAR 15=DATASEC 16=FLOAT
        // 17=DECL_TAG 18=TYPE_TAG 19=ENUM64
        #[allow(clippy::match_same_arms)]
        match kind {
            1 => 4,             // INT: encoding u32
            3 => 12,            // ARRAY: 3×u32
            4 | 5 => 12 * vlen, // STRUCT/UNION: member = {name_off, type, offset}
            6 => 8 * vlen,      // ENUM: {name_off, val}
            13 => 8 * vlen,     // FUNC_PROTO: {name_off, type} per param
            14 => 4,            // VAR: linkage u32
            15 => 12 * vlen,    // DATASEC: {type, offset, size}
            17 => 4,            // DECL_TAG: component_idx
            19 => 12 * vlen,    // ENUM64: {name_off, val_lo, val_hi}
            _ => 0, // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG
        }
    }

    /// Find the byte offset of a named field within a named struct.
    ///
    /// Scans the entire type section linearly. For the 7 lookups we do at
    /// startup this is fine — the kernel BTF is parsed in ~20ms.
    fn struct_field_offset(&self, struct_name: &str, field_name: &str) -> Result<u64> {
        let base = self.hdr_len + self.type_off;
        let end = base + self.type_len;
        let mut pos = base;

        while pos + 12 <= end {
            let name_off = self.read_u32(pos);
            let info = self.read_u32(pos + 4);
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;

            if kind == BTF_KIND_STRUCT && self.string(name_off) == struct_name {
                // Scan members (each is 12 bytes: name_off, type, bit_offset).
                let member_base = pos + 12;
                for i in 0..vlen {
                    let m_off = member_base + i * 12;
                    let m_name_off = self.read_u32(m_off);
                    let m_bit_offset = self.read_u32(m_off + 8);
                    if self.string(m_name_off) == field_name {
                        return Ok(u64::from(m_bit_offset) / 8);
                    }
                }
                bail!("field '{field_name}' not found in struct '{struct_name}'");
            }

            pos += 12 + Self::extra_bytes(kind, vlen);
        }

        bail!("struct '{struct_name}' not found in kernel BTF");
    }
}

/// Resolve all kernel struct field offsets needed by the eBPF probes.
pub fn resolve_task_field_offsets() -> Result<TaskFieldOffsets> {
    let btf = Btf::from_sys_fs()?;

    Ok(TaskFieldOffsets {
        task_real_parent: btf
            .struct_field_offset("task_struct", "real_parent")
            .context("task_struct.real_parent")?,
        task_tgid: btf
            .struct_field_offset("task_struct", "tgid")
            .context("task_struct.tgid")?,
        task_cred: btf
            .struct_field_offset("task_struct", "cred")
            .context("task_struct.cred")?,
        cred_euid: btf
            .struct_field_offset("cred", "euid")
            .context("cred.euid")?,
        task_signal: btf
            .struct_field_offset("task_struct", "signal")
            .context("task_struct.signal")?,
        signal_tty: btf
            .struct_field_offset("signal_struct", "tty")
            .context("signal_struct.tty")?,
        tty_index: btf
            .struct_field_offset("tty_struct", "index")
            .context("tty_struct.index")?,
    })
}
