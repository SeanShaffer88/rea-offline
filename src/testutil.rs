//! Test-support utilities.
//!
//! Compiled in both `dev` and `test` profiles so integration tests
//! (`tests/`) and the CI smoke script can build realistic fixtures — in
//! particular a **structurally valid PE** with an arbitrary import table —
//! without checking binary blobs into the repository.
//!
//! Nothing here is used by the shipped CLI paths.

#![allow(clippy::needless_range_loop)]

/// Description of one imported function.
#[derive(Debug, Clone, PartialEq)]
pub enum Import {
    /// Import by name.
    Named(&'static str),
    /// Import by ordinal.
    Ordinal(u16),
}

/// Builder for a minimal but structurally valid PE32+ image.
///
/// Layout (all offsets fixed, one `.text` section at RVA 0x1000 → raw 0x200):
/// ```text
/// 0x000  DOS header (e_lfanew = 0x80)
/// 0x080  PE signature + COFF header
/// 0x098  Optional header (PE32+, 240 bytes)
/// 0x188  Section table (1 entry, 40 bytes)
/// 0x1b0  (padding)
/// 0x200  .text raw data (0x800 bytes): import descriptors, thunks,
///        hint/name entries, DLL name strings
/// ```
/// Adding overlay bytes appends after the end of `.text` raw data.
#[derive(Debug, Clone)]
pub struct PeBuilder {
    machine: u16,
    subsystem: u16,
    dll_characteristics: u16,
    timestamp: u32,
    entry_point: u32,
    sections: Vec<(String, u32, u32, u32)>, // (name, vsize, rawsize, characteristics)
    imports: Vec<(String, Vec<Import>)>,
    signed: bool,
    overlay: Vec<u8>,
}

impl Default for PeBuilder {
    fn default() -> Self {
        PeBuilder {
            machine: 0x8664,   // x86-64
            subsystem: 3,      // windows-console
            dll_characteristics: 0x4160, // high_entropy_va | dynamic_base | nx_compat | guard_cf
            timestamp: 0x6500_0000,
            entry_point: 0x1000,
            // .text must be big enough to hold the import scaffolding below.
            sections: vec![(".text".to_string(), 0x800, 0x800, 0x6000_0020)],
            imports: vec![],
            signed: false,
            overlay: vec![],
        }
    }
}

impl PeBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn machine(mut self, machine: u16) -> Self { self.machine = machine; self }
    pub fn subsystem(mut self, subsystem: u16) -> Self { self.subsystem = subsystem; self }
    pub fn dll_characteristics(mut self, value: u16) -> Self { self.dll_characteristics = value; self }
    pub fn timestamp(mut self, value: u32) -> Self { self.timestamp = value; self }
    pub fn entry_point(mut self, value: u32) -> Self { self.entry_point = value; self }
    pub fn overlay(mut self, bytes: usize) -> Self { self.overlay = vec![0x41; bytes]; self }
    /// Presence-only Authenticode: appends a dummy WIN_CERTIFICATE (not a valid signature).
    pub fn signed(mut self, on: bool) -> Self { self.signed = on; self }

    /// Replace the section table (first entry must stay at RVA 0x1000 so the
    /// import scaffolding below remains valid).
    pub fn sections(mut self, sections: Vec<(String, u32, u32, u32)>) -> Self {
        self.sections = sections;
        self
    }

    /// Declare imports for one DLL (e.g. `("KERNEL32.dll", vec![Import::Named("Sleep")])`).
    pub fn imports(mut self, dll: &str, funcs: Vec<Import>) -> Self {
        self.imports.push((dll.to_string(), funcs));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        // 0x200 header + one full .text extent: the import descriptors,
        // thunk tables, hint/name entries and DLL names live at fixed RVAs
        // inside it, so shrinking this buffer breaks the builder.
        let mut d = vec![0u8; 0x200 + 0x800];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        d[coff..coff + 2].copy_from_slice(&self.machine.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&(self.sections.len() as u16).to_le_bytes());
        d[coff + 4..coff + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        d[opt + 16..opt + 20].copy_from_slice(&self.entry_point.to_le_bytes());
        d[opt + 68..opt + 70].copy_from_slice(&self.subsystem.to_le_bytes());
        d[opt + 70..opt + 72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        d[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        d[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumRvaAndSizes
        let dd = opt + 112;

        // Import scaffolding lives at fixed offsets inside .text.
        let import_dir_rva = 0x1100u32;
        let raw = |rva: u32| (0x200 + (rva - 0x1000)) as usize;
        let mut desc_off = raw(import_dir_rva);
        let mut thunk_rva = 0x1300u32; // lookup tables
        let mut hint_rva = 0x1500u32;  // hint/name entries
        let mut dll_rva = 0x1700u32;   // DLL name strings
        let mut descriptors: Vec<(u32, u32)> = Vec::new();

        for (dll, funcs) in &self.imports {
            let name_off = raw(dll_rva);
            let bytes = dll.as_bytes();
            d[name_off..name_off + bytes.len()].copy_from_slice(bytes);
            let mut thunk_off = raw(thunk_rva);
            for func in funcs {
                match func {
                    Import::Named(name) => {
                        let hn_off = raw(hint_rva);
                        d[hn_off + 2..hn_off + 2 + name.len()].copy_from_slice(name.as_bytes());
                        d[thunk_off..thunk_off + 8].copy_from_slice(&(hint_rva as u64).to_le_bytes());
                        hint_rva += 0x40;
                    }
                    Import::Ordinal(ord) => {
                        let value = 0x8000_0000_0000_0000u64 | (*ord as u64);
                        d[thunk_off..thunk_off + 8].copy_from_slice(&value.to_le_bytes());
                    }
                }
                thunk_off += 8;
            }
            descriptors.push((thunk_rva, dll_rva));
            thunk_rva = thunk_rva + 0x40;
            dll_rva += 0x40;
        }

        // The import scaffolding lives inside the first section, so that
        // section must be big enough even if the caller asked for a tiny one
        // (a real linker would do the same).
        let mut sections = self.sections.clone();
        if !descriptors.is_empty() && !sections.is_empty() {
            const NEEDED: u32 = 0x800;
            sections[0].1 = sections[0].1.max(NEEDED);
            sections[0].2 = sections[0].2.max(NEEDED);
        }
        if !descriptors.is_empty() {
            // Descriptors: OriginalFirstThunk, Name, FirstThunk.
            for (oft, name) in &descriptors {
                d[desc_off..desc_off + 4].copy_from_slice(&oft.to_le_bytes());
                d[desc_off + 12..desc_off + 16].copy_from_slice(&name.to_le_bytes());
                d[desc_off + 16..desc_off + 20].copy_from_slice(&oft.to_le_bytes());
                desc_off += 20;
            }
            d[dd + 8..dd + 12].copy_from_slice(&import_dir_rva.to_le_bytes());
            d[dd + 12..dd + 16].copy_from_slice(&(descriptors.len() as u32 * 20).to_le_bytes());
        }

        // Section table.
        let sec = opt + 240;
        let mut last_end = 0u64;
        // Sections get consecutive raw extents (as a real linker lays them
        // out); overlapping extents would make overlay arithmetic nonsense.
        let mut raw_cursor = 0x200u32;
        for (i, (name, vsize, rawsize, chars)) in sections.iter().enumerate() {
            let off = sec + i * 40;
            let nb = name.as_bytes();
            d[off..off + nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
            d[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
            let va = 0x1000u32 * (i as u32 + 1);
            d[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            d[off + 16..off + 20].copy_from_slice(&rawsize.to_le_bytes());
            d[off + 20..off + 24].copy_from_slice(&raw_cursor.to_le_bytes());
            d[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
            last_end = last_end.max((raw_cursor + *rawsize) as u64);
            raw_cursor += (*rawsize).max(0x200);
        }
        if d.len() < last_end as usize {
            d.resize(last_end as usize, 0);
        }

        // A presence-only dummy WIN_CERTIFICATE still needs actual bytes.
        // Keep the caller's overlay separate, so tests can prove that data
        // after the certificate remains visible to overlay accounting.
        if self.signed {
            let cert_off = d.len() as u32;
            d[dd + 32..dd + 36].copy_from_slice(&cert_off.to_le_bytes());
            d[dd + 36..dd + 40].copy_from_slice(&8u32.to_le_bytes());
            d.extend_from_slice(&8u32.to_le_bytes()); // dwLength
            d.extend_from_slice(&0x0200u16.to_le_bytes()); // revision
            d.extend_from_slice(&2u16.to_le_bytes()); // PKCS signed data type
        }
        if !self.overlay.is_empty() {
            d.extend_from_slice(&self.overlay);
        }
        d
    }
}

/// A small, realistic-looking "installer" payload with capability strings,
/// used by tests and the CI smoke run.
pub fn demo_installer_bytes() -> Vec<u8> {
    let mut pe = PeBuilder::new()
        .imports("KERNEL32.dll", vec![Import::Named("Sleep"), Import::Named("CreateFileW")])
        .imports("WININET.dll", vec![Import::Named("InternetOpenW"), Import::Named("InternetReadFile")])
        .build();
    pe.extend_from_slice(
        b"demo-payload\x00https://example.invalid/update\x00WinHttp\x00powershell\x00",
    );
    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_parseable_pe() {
        let bytes = PeBuilder::new()
            .imports("KERNEL32.dll", vec![Import::Named("CreateRemoteThread")])
            .build();
        assert!(bytes.starts_with(b"MZ"));
        let info = crate::rea_bridge::parse_pe_bytes(&bytes).expect("must parse");
        assert_eq!(info.machine, "x86-64");
        assert_eq!(info.imports, vec!["KERNEL32.dll".to_string()]);
        assert!(info.imported_functions.contains(&"KERNEL32.dll!CreateRemoteThread".to_string()));
    }

    #[test]
    fn overlay_and_signature_flags() {
        let bytes = PeBuilder::new().overlay(100).signed(true).build();
        let info = crate::rea_bridge::parse_pe_bytes(&bytes).unwrap();
        assert!(info.signed);
        assert_eq!(info.overlay_size, 100, "the certificate must not hide appended overlay bytes");
    }
}
