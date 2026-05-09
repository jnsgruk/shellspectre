//! Minimal BTF parser for resolving struct field byte offsets from the kernel's
//! `/sys/kernel/btf/vmlinux`. Only supports `BTF_KIND_STRUCT` member lookups —
//! just enough to read `task_struct`, `cred`, `signal_struct`, and `tty_struct`
//! field positions at runtime.

use anyhow::{Context, Result, bail};
use shspectr_common::TaskFieldOffsets;
use std::fs;

// BTF format constants (from include/uapi/linux/btf.h).
const BTF_MAGIC: u16 = 0xEB9F;
const BTF_KIND_STRUCT: u32 = 4;

/// Parsed BTF data with references into the raw byte buffer.
#[derive(Debug)]
struct Btf {
    data: Vec<u8>,
    hdr_len: usize,
    type_off: usize,
    type_len: usize,
    str_off: usize,
    str_len: usize,
}

impl Btf {
    /// Parse BTF data from raw bytes.
    fn from_bytes(data: Vec<u8>) -> Result<Self> {
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
        let str_len = u32::from_ne_bytes(data[20..24].try_into()?) as usize;
        if hdr_len < 24 || hdr_len > data.len() {
            bail!("invalid BTF header length {hdr_len}");
        }
        let type_end = hdr_len
            .checked_add(type_off)
            .and_then(|start| start.checked_add(type_len))
            .context("BTF type section overflows header bounds")?;
        let str_start = hdr_len
            .checked_add(str_off)
            .context("BTF string section overflows header bounds")?;
        let str_end = str_start
            .checked_add(str_len)
            .context("BTF string table overflows header bounds")?;
        if type_end > data.len() || str_end > data.len() || str_start < type_end {
            bail!("BTF sections extend beyond the input buffer");
        }

        Ok(Self {
            data,
            hdr_len,
            type_off,
            type_len,
            str_off,
            str_len,
        })
    }

    /// Read BTF from the kernel's sysfs.
    fn from_sys_fs() -> Result<Self> {
        let data = fs::read("/sys/kernel/btf/vmlinux").context("failed to read kernel BTF")?;
        Self::from_bytes(data)
    }

    /// Look up a null-terminated string from the BTF string table.
    fn string(&self, offset: u32) -> Result<&str> {
        let str_base = self.hdr_len + self.str_off;
        let str_end = str_base + self.str_len;
        let start = str_base + offset as usize;
        if start >= str_end {
            bail!("BTF string offset {offset} outside string table");
        }
        let end = self.data[start..str_end]
            .iter()
            .position(|&b| b == 0)
            .map_or(str_end, |p| start + p);
        std::str::from_utf8(&self.data[start..end])
            .context("BTF string table contains invalid UTF-8")
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

            if kind == BTF_KIND_STRUCT && self.string(name_off)? == struct_name {
                // Scan members (each is 12 bytes: name_off, type, bit_offset).
                let member_base = pos + 12;
                for i in 0..vlen {
                    let m_off = member_base + i * 12;
                    if m_off + 12 > end {
                        bail!("truncated BTF struct member list for '{struct_name}'");
                    }
                    let m_name_off = self.read_u32(m_off);
                    let m_bit_offset = self.read_u32(m_off + 8);
                    if self.string(m_name_off)? == field_name {
                        return Ok(u64::from(m_bit_offset) / 8);
                    }
                }
                bail!("field '{field_name}' not found in struct '{struct_name}'");
            }

            let step = 12 + Self::extra_bytes(kind, vlen);
            pos = pos.checked_add(step).context("BTF type walk overflowed")?;
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
        task_files: btf
            .struct_field_offset("task_struct", "files")
            .context("task_struct.files")?,
        files_fdt: btf
            .struct_field_offset("files_struct", "fdt")
            .context("files_struct.fdt")?,
        fdt_fd: btf
            .struct_field_offset("fdtable", "fd")
            .context("fdtable.fd")?,
        file_inode: btf
            .struct_field_offset("file", "f_inode")
            .context("file.f_inode")?,
        inode_rdev: btf
            .struct_field_offset("inode", "i_rdev")
            .context("inode.i_rdev")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic BTF blob with one struct containing the
    /// given fields. Each field is placed at `index * 8` bytes (bit offset
    /// = index * 64).
    fn make_btf(struct_name: &str, fields: &[&str]) -> Vec<u8> {
        // String table: "\0" + struct_name + "\0" + field1 + "\0" + ...
        let mut str_table = vec![0u8]; // index 0 = empty string
        let struct_name_off = str_table.len() as u32;
        str_table.extend_from_slice(struct_name.as_bytes());
        str_table.push(0);

        let mut field_name_offs = Vec::new();
        for field in fields {
            field_name_offs.push(str_table.len() as u32);
            str_table.extend_from_slice(field.as_bytes());
            str_table.push(0);
        }

        // Type section: one BTF_KIND_STRUCT entry
        // Type header: name_off(4) + info(4) + size(4) = 12 bytes
        // Members: name_off(4) + type(4) + bit_offset(4) = 12 bytes each
        let vlen = fields.len() as u32;
        let info = (BTF_KIND_STRUCT << 24) | vlen;
        let struct_size = (fields.len() * 8) as u32;

        let mut type_section = Vec::new();
        type_section.extend_from_slice(&struct_name_off.to_ne_bytes());
        type_section.extend_from_slice(&info.to_ne_bytes());
        type_section.extend_from_slice(&struct_size.to_ne_bytes());

        for (i, &name_off) in field_name_offs.iter().enumerate() {
            let bit_offset = (i as u32) * 64; // 8 bytes per field
            type_section.extend_from_slice(&name_off.to_ne_bytes());
            type_section.extend_from_slice(&0u32.to_ne_bytes()); // type id (unused)
            type_section.extend_from_slice(&bit_offset.to_ne_bytes());
        }

        // BTF header (24 bytes)
        let hdr_len: u32 = 24;
        let type_off: u32 = 0;
        let type_len = type_section.len() as u32;
        let str_off = type_len;
        let str_len = str_table.len() as u32;

        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_ne_bytes()); // magic
        data.push(1); // version
        data.push(0); // flags
        data.extend_from_slice(&hdr_len.to_ne_bytes());
        data.extend_from_slice(&type_off.to_ne_bytes());
        data.extend_from_slice(&type_len.to_ne_bytes());
        data.extend_from_slice(&str_off.to_ne_bytes());
        data.extend_from_slice(&str_len.to_ne_bytes());

        data.extend_from_slice(&type_section);
        data.extend_from_slice(&str_table);

        data
    }

    #[test]
    fn struct_field_offset_finds_first_field() {
        let data = make_btf("my_struct", &["alpha", "beta", "gamma"]);
        let btf = Btf::from_bytes(data).unwrap();
        assert_eq!(btf.struct_field_offset("my_struct", "alpha").unwrap(), 0);
    }

    #[test]
    fn struct_field_offset_finds_later_field() {
        let data = make_btf("my_struct", &["alpha", "beta", "gamma"]);
        let btf = Btf::from_bytes(data).unwrap();
        assert_eq!(btf.struct_field_offset("my_struct", "beta").unwrap(), 8);
        assert_eq!(btf.struct_field_offset("my_struct", "gamma").unwrap(), 16);
    }

    #[test]
    fn struct_field_offset_missing_field() {
        let data = make_btf("my_struct", &["alpha"]);
        let btf = Btf::from_bytes(data).unwrap();
        let err = btf.struct_field_offset("my_struct", "missing").unwrap_err();
        assert!(
            err.to_string().contains("field 'missing' not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn struct_field_offset_missing_struct() {
        let data = make_btf("my_struct", &["alpha"]);
        let btf = Btf::from_bytes(data).unwrap();
        let err = btf
            .struct_field_offset("other_struct", "alpha")
            .unwrap_err();
        assert!(
            err.to_string().contains("struct 'other_struct' not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_bytes_rejects_short_data() {
        assert!(Btf::from_bytes(vec![0; 10]).is_err());
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut data = vec![0u8; 24];
        data[0] = 0xFF;
        data[1] = 0xFF;
        let err = Btf::from_bytes(data).unwrap_err();
        assert!(err.to_string().contains("bad BTF magic"));
    }

    #[test]
    fn extra_bytes_struct_members() {
        assert_eq!(Btf::extra_bytes(4, 3), 36); // STRUCT: 12 * 3
        assert_eq!(Btf::extra_bytes(4, 0), 0);
    }

    #[test]
    fn extra_bytes_other_kinds() {
        assert_eq!(Btf::extra_bytes(1, 0), 4); // INT
        assert_eq!(Btf::extra_bytes(3, 0), 12); // ARRAY
        assert_eq!(Btf::extra_bytes(2, 0), 0); // PTR
        assert_eq!(Btf::extra_bytes(6, 2), 16); // ENUM: 8 * 2
    }

    #[test]
    fn struct_field_offset_with_multiple_structs() {
        // Build BTF with two structs
        let mut str_table = vec![0u8]; // index 0 = empty

        let first_name_off = str_table.len() as u32;
        str_table.extend_from_slice(b"other_struct\0");
        let first_field_off = str_table.len() as u32;
        str_table.extend_from_slice(b"x\0");

        let second_name_off = str_table.len() as u32;
        str_table.extend_from_slice(b"target_struct\0");
        let second_field_off = str_table.len() as u32;
        str_table.extend_from_slice(b"y\0");

        // Type section: two structs
        let mut type_section = Vec::new();

        // Struct 1: other_struct { x }
        let info1 = (BTF_KIND_STRUCT << 24) | 1;
        type_section.extend_from_slice(&first_name_off.to_ne_bytes());
        type_section.extend_from_slice(&info1.to_ne_bytes());
        type_section.extend_from_slice(&8u32.to_ne_bytes()); // size
        type_section.extend_from_slice(&first_field_off.to_ne_bytes()); // member name
        type_section.extend_from_slice(&0u32.to_ne_bytes()); // type
        type_section.extend_from_slice(&0u32.to_ne_bytes()); // bit_offset = 0

        // Struct 2: target_struct { y } at bit_offset 128 (byte 16)
        let info2 = (BTF_KIND_STRUCT << 24) | 1;
        type_section.extend_from_slice(&second_name_off.to_ne_bytes());
        type_section.extend_from_slice(&info2.to_ne_bytes());
        type_section.extend_from_slice(&24u32.to_ne_bytes()); // size
        type_section.extend_from_slice(&second_field_off.to_ne_bytes()); // member name
        type_section.extend_from_slice(&0u32.to_ne_bytes()); // type
        type_section.extend_from_slice(&128u32.to_ne_bytes()); // bit_offset = 128 → byte 16

        // Build BTF header
        let hdr_len: u32 = 24;
        let type_len = type_section.len() as u32;
        let str_off = type_len;
        let str_len = str_table.len() as u32;

        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_ne_bytes());
        data.push(1);
        data.push(0);
        data.extend_from_slice(&hdr_len.to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes()); // type_off
        data.extend_from_slice(&type_len.to_ne_bytes());
        data.extend_from_slice(&str_off.to_ne_bytes());
        data.extend_from_slice(&str_len.to_ne_bytes());
        data.extend_from_slice(&type_section);
        data.extend_from_slice(&str_table);

        let btf = Btf::from_bytes(data).unwrap();
        // Should find y in target_struct at byte offset 16
        assert_eq!(btf.struct_field_offset("target_struct", "y").unwrap(), 16);
        // Should still find x in other_struct at byte offset 0
        assert_eq!(btf.struct_field_offset("other_struct", "x").unwrap(), 0);
    }

    #[test]
    fn from_bytes_rejects_truncated_sections() {
        let mut data = make_btf("my_struct", &["alpha"]);
        data[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        let err = Btf::from_bytes(data).unwrap_err();
        assert!(
            err.to_string().contains("BTF type section")
                || err.to_string().contains("extend beyond")
        );
    }

    #[test]
    fn struct_field_offset_rejects_bad_string_offset() {
        let mut data = make_btf("my_struct", &["alpha"]);
        let type_section_start = 24usize;
        data[type_section_start..type_section_start + 4].copy_from_slice(&999u32.to_ne_bytes());
        let btf = Btf::from_bytes(data).unwrap();
        let err = btf.struct_field_offset("my_struct", "alpha").unwrap_err();
        assert!(err.to_string().contains("string offset"));
    }
}
