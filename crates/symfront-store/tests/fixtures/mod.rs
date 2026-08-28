//! Synthetic test fixtures: minimal-but-valid PE images and PDBs built in
//! memory, so tests are self-contained and can construct edge cases (age
//! mismatches, missing streams) deterministically. Real `symstore.exe`
//! accepts these files (see the differential test), so they are not merely
//! self-consistent with our parser.

/// Minimal PE image. `pe32plus` selects PE32+ (x64) vs PE32 (x86) optional
/// headers; the store hash is `{timestamp:08X}{size_of_image:x}` either way.
pub fn minimal_pe(timestamp: u32, size_of_image: u32, pe32plus: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // DOS header: "MZ", e_lfanew = 0x80.
    out.extend_from_slice(b"MZ");
    out.resize(0x3c, 0);
    out.extend_from_slice(&0x80u32.to_le_bytes());
    out.resize(0x80, 0);
    // COFF header.
    out.extend_from_slice(b"PE\0\0");
    let machine: u16 = if pe32plus { 0x8664 } else { 0x14c };
    out.extend_from_slice(&machine.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // sections
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&[0; 8]); // symtab ptr, nsyms
    let opt_size: u16 = if pe32plus { 0xF0 } else { 0xE0 };
    out.extend_from_slice(&opt_size.to_le_bytes());
    let characteristics: u16 = if pe32plus { 0x0022 } else { 0x0102 };
    out.extend_from_slice(&characteristics.to_le_bytes());
    // Optional header.
    let opt_start = out.len();
    let magic: u16 = if pe32plus { 0x20b } else { 0x10b };
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&[14, 0]); // linker version
    for v in [0x200u32, 0, 0, 0x1000, 0x1000] {
        out.extend_from_slice(&v.to_le_bytes()); // code/init/uninit, entry, base of code
    }
    if pe32plus {
        out.extend_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
    } else {
        out.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfData
        out.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
    }
    out.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    out.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    for v in [6u16, 0, 0, 0, 6, 0] {
        out.extend_from_slice(&v.to_le_bytes()); // OS/image/subsystem versions
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    out.extend_from_slice(&size_of_image.to_le_bytes());
    out.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    out.extend_from_slice(&0u32.to_le_bytes()); // Checksum
    out.extend_from_slice(&3u16.to_le_bytes()); // Subsystem: console
    out.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    if pe32plus {
        for v in [0x100000u64, 0x1000, 0x100000, 0x1000] {
            out.extend_from_slice(&v.to_le_bytes()); // stack/heap
        }
    } else {
        for v in [0x100000u32, 0x1000, 0x100000, 0x1000] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    out.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    out.resize(out.len() + 16 * 8, 0); // data directories
    assert_eq!(out.len() - opt_start, opt_size as usize);
    // One .text section.
    out.extend_from_slice(b".text\0\0\0");
    for v in [0x1000u32, 0x1000, 0x200, 0x200, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    out.resize(0x200, 0);
    // Section body.
    out.push(0xc3);
    out.extend_from_slice(b"symfront synthetic test binary\0");
    out.resize(0x400, 0);
    out
}

const MSF_BS: usize = 512;

fn msf_block(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= MSF_BS);
    let mut b = data.to_vec();
    b.resize(MSF_BS, 0);
    b
}

/// Minimal MSF 7.0 PDB with a PDB info stream (GUID + `info_age`) and,
/// optionally, a DBI stream carrying `dbi_age`. The store hash uses the DBI
/// age when that stream exists.
pub fn minimal_msf_pdb(guid: [u8; 16], info_age: u32, dbi_age: Option<u32>) -> Vec<u8> {
    // Blocks: 0 superblock, 1+2 free page maps, 3 info stream,
    // [4 DBI stream,] then directory, then block map.
    let with_dbi = dbi_age.is_some();
    let num_streams: u32 = if with_dbi { 4 } else { 2 };
    let stream_sizes: Vec<u32> = if with_dbi {
        vec![0, 28, 0, 12]
    } else {
        vec![0, 28]
    };
    let dir_bytes = 4 + 4 * stream_sizes.len() + 4 + if with_dbi { 4 } else { 0 };
    let (dbi_block, dir_block, map_block, num_blocks) = if with_dbi {
        (Some(4u32), 5u32, 6u32, 7u32)
    } else {
        (None, 4u32, 5u32, 6u32)
    };

    let mut superblock = Vec::new();
    superblock.extend_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    for v in [MSF_BS as u32, 1, num_blocks, dir_bytes as u32, 0, map_block] {
        superblock.extend_from_slice(&v.to_le_bytes());
    }

    let mut info = Vec::new();
    for v in [20000404u32, 0x11223344, info_age] {
        info.extend_from_slice(&v.to_le_bytes());
    }
    info.extend_from_slice(&guid);

    let mut directory = Vec::new();
    directory.extend_from_slice(&num_streams.to_le_bytes());
    for s in &stream_sizes {
        directory.extend_from_slice(&s.to_le_bytes());
    }
    directory.extend_from_slice(&3u32.to_le_bytes()); // info stream block list
    if with_dbi {
        directory.extend_from_slice(&dbi_block.unwrap().to_le_bytes());
    }
    assert_eq!(directory.len(), dir_bytes);

    let mut out = Vec::new();
    out.extend(msf_block(&superblock));
    out.extend(vec![0xffu8; MSF_BS]); // free page map 1
    out.extend(vec![0xffu8; MSF_BS]); // free page map 2
    out.extend(msf_block(&info));
    if let Some(age) = dbi_age {
        let mut dbi = Vec::new();
        dbi.extend_from_slice(&(-1i32).to_le_bytes());
        dbi.extend_from_slice(&19990903u32.to_le_bytes());
        dbi.extend_from_slice(&age.to_le_bytes());
        out.extend(msf_block(&dbi));
    }
    out.extend(msf_block(&directory));
    out.extend(msf_block(&dir_block.to_le_bytes()));
    assert_eq!(out.len(), num_blocks as usize * MSF_BS);
    out
}

/// Minimal portable PDB (ECMA-335 metadata root with a `#Pdb` stream).
pub fn minimal_portable_pdb(guid: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"BSJB");
    out.extend_from_slice(&[1, 0, 1, 0]); // major, minor
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    let version = b"PDB v1.0\0\0\0\0"; // pre-padded to 4
    out.extend_from_slice(&(version.len() as u32).to_le_bytes());
    out.extend_from_slice(version);
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&1u16.to_le_bytes()); // stream count
                                                // Stream header for #Pdb: offset fixed up after layout.
    let header_pos = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // offset (patched)
    out.extend_from_slice(&20u32.to_le_bytes()); // size
    out.extend_from_slice(b"#Pdb\0\0\0\0"); // name, padded to 4
    let data_off = out.len() as u32;
    out[header_pos..header_pos + 4].copy_from_slice(&data_off.to_le_bytes());
    out.extend_from_slice(&guid);
    out.extend_from_slice(&0xdeadbeefu32.to_le_bytes()); // stamp
    out
}

/// Format a GUID the way symbol-store keys do (Data1-3 little-endian).
pub fn guid_hex(g: &[u8; 16]) -> String {
    format!(
        "{:08X}{:04X}{:04X}{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8..16]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    )
}
