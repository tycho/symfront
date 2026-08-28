//! Identify files the way symstore.exe does and compute their symbol-store
//! hash (the directory name under `<file>/<HASH>/`).
//!
//! Identification is by content, not extension, so every PE flavor
//! (exe/dll/sys/ocx/com/vxd/scr/…) is picked up:
//!
//! - PE image: hash = `%08X` TimeDateStamp (uppercase) + `%x` SizeOfImage
//!   (lowercase, unpadded), e.g. `5685393Cbf000`.
//! - PDB (MSF 7.0): hash = GUID as 32 uppercase hex digits + `%x` Age
//!   (lowercase), e.g. `FBD847692A3A46DE84017F480ACF33891`. The age comes
//!   from the DBI stream when present (what debuggers request via the PE's
//!   RSDS record), falling back to the PDB info stream.
//! - Portable PDB (.NET, `BSJB` magic): hash = GUID from the `#Pdb` stream
//!   + literal `FFFFFFFF` (SSQP convention; verified against msdl).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Pe,
    Pdb,
}

impl FileKind {
    /// The type tag symstore writes into refs.ptr: binaries are `bin`,
    /// symbols are `pri` (private).
    pub fn refs_tag(self) -> &'static str {
        match self {
            FileKind::Pe => "bin",
            FileKind::Pdb => "pri",
        }
    }
}

const MSF7_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// Identify a file and compute its store hash. `Ok(None)` means the file is
/// neither a PE image nor a supported PDB (symstore would skip it too).
pub fn identify(path: &Path) -> Result<Option<(FileKind, String)>> {
    let mut f = File::open(path).map_err(|e| Error::io(path, e))?;
    let mut magic = [0u8; 32];
    let n = read_up_to(&mut f, &mut magic).map_err(|e| Error::io(path, e))?;
    if n >= 2 && &magic[0..2] == b"MZ" {
        return Ok(pe_hash(&mut f)
            .map_err(|e| Error::io(path, e))?
            .map(|h| (FileKind::Pe, h)));
    }
    if n == 32 && &magic == MSF7_MAGIC {
        return Ok(pdb_hash(&mut f)
            .map_err(|e| Error::io(path, e))?
            .map(|h| (FileKind::Pdb, h)));
    }
    if n >= 4 && &magic[0..4] == b"BSJB" {
        return Ok(portable_pdb_hash(&mut f)
            .map_err(|e| Error::io(path, e))?
            .map(|h| (FileKind::Pdb, h)));
    }
    Ok(None)
}

fn read_up_to(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = f.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

fn read_exact_at(f: &mut File, off: u64, buf: &mut [u8]) -> std::io::Result<bool> {
    f.seek(SeekFrom::Start(off))?;
    let n = read_up_to(f, buf)?;
    Ok(n == buf.len())
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// TimeDateStamp + SizeOfImage from the PE headers; None if the MZ file has
/// no valid PE signature (plain DOS executable).
fn pe_hash(f: &mut File) -> std::io::Result<Option<String>> {
    let mut lfanew = [0u8; 4];
    if !read_exact_at(f, 0x3c, &mut lfanew)? {
        return Ok(None);
    }
    let pe_off = u32le(&lfanew) as u64;
    if pe_off == 0 || pe_off > 0x1000_0000 {
        return Ok(None);
    }
    // "PE\0\0" + COFF header (20 bytes) + start of the optional header.
    // SizeOfImage sits at optional header offset 56 for PE32 and PE32+.
    let mut hdr = [0u8; 4 + 20 + 60];
    if !read_exact_at(f, pe_off, &mut hdr)? {
        return Ok(None);
    }
    if &hdr[0..4] != b"PE\0\0" {
        return Ok(None);
    }
    let timestamp = u32le(&hdr[8..12]);
    let opt_size = u16le(&hdr[20..22]);
    let opt_magic = u16le(&hdr[24..26]);
    if opt_size < 60 || (opt_magic != 0x10b && opt_magic != 0x20b) {
        return Ok(None);
    }
    let size_of_image = u32le(&hdr[24 + 56..24 + 60]);
    Ok(Some(format!("{timestamp:08X}{size_of_image:x}")))
}

/// GUID + Age from the PDB info stream (stream 1) of an MSF 7 file.
fn pdb_hash(f: &mut File) -> std::io::Result<Option<String>> {
    // SuperBlock immediately after the 32-byte magic.
    let mut sb = [0u8; 24];
    if !read_exact_at(f, 32, &mut sb)? {
        return Ok(None);
    }
    let block_size = u32le(&sb[0..4]) as u64;
    let num_dir_bytes = u32le(&sb[12..16]) as u64;
    let block_map_addr = u32le(&sb[20..24]) as u64;
    if !(512..=65536).contains(&block_size)
        || !block_size.is_power_of_two()
        || num_dir_bytes == 0
        || num_dir_bytes > 64 * 1024 * 1024
    {
        return Ok(None);
    }
    // The block map lists the blocks holding the stream directory.
    let dir_block_count = num_dir_bytes.div_ceil(block_size);
    let mut map = vec![0u8; (dir_block_count * 4) as usize];
    if !read_exact_at(f, block_map_addr * block_size, &mut map)? {
        return Ok(None);
    }
    let mut directory = Vec::with_capacity(num_dir_bytes as usize);
    for i in 0..dir_block_count {
        let block = u32le(&map[(i * 4) as usize..]) as u64;
        let want = (num_dir_bytes - directory.len() as u64).min(block_size) as usize;
        let mut chunk = vec![0u8; want];
        if !read_exact_at(f, block * block_size, &mut chunk)? {
            return Ok(None);
        }
        directory.extend_from_slice(&chunk);
    }
    // Directory: numStreams, streamSizes[], then each stream's block list.
    if directory.len() < 4 {
        return Ok(None);
    }
    let num_streams = u32le(&directory[0..4]) as usize;
    if num_streams < 2 || directory.len() < 4 + num_streams * 4 {
        return Ok(None);
    }
    let size_of = |i: usize| -> u64 {
        let raw = u32le(&directory[4 + i * 4..]);
        if raw == u32::MAX {
            0 // nil stream
        } else {
            raw as u64
        }
    };
    if size_of(1) < 28 {
        return Ok(None);
    }
    // First block of stream `i`: skip the block lists of streams before it.
    // Headers fit in a stream's first block (block_size >= 512).
    let first_block_of = |i: usize| -> Option<u64> {
        let mut idx = 4 + num_streams * 4;
        for j in 0..i {
            idx += (size_of(j).div_ceil(block_size) * 4) as usize;
        }
        if directory.len() < idx + 4 {
            None
        } else {
            Some(u32le(&directory[idx..]) as u64)
        }
    };
    // PDB info stream (1) header: Version, Signature, Age, Guid[16].
    let Some(info_block) = first_block_of(1) else {
        return Ok(None);
    };
    let mut info = [0u8; 28];
    if !read_exact_at(f, info_block * block_size, &mut info)? {
        return Ok(None);
    }
    let mut age = u32le(&info[8..12]);
    let g = &info[12..28];
    // The symbol-server key uses the DBI stream's age when the DBI stream is
    // present (SSQP convention): post-link tools bump the PDB info stream's
    // age, but debuggers request the age recorded in the PE's RSDS record,
    // which matches DBI.
    if num_streams > 3 && size_of(3) >= 12 {
        if let Some(dbi_block) = first_block_of(3) {
            let mut dbi = [0u8; 12];
            if read_exact_at(f, dbi_block * block_size, &mut dbi)? {
                age = u32le(&dbi[8..12]);
            }
        }
    }
    let guid = format_guid(g);
    Ok(Some(format!("{guid}{age:x}")))
}

fn format_guid(g: &[u8]) -> String {
    format!(
        "{:08X}{:04X}{:04X}{}",
        u32le(&g[0..4]),
        u16le(&g[4..6]),
        u16le(&g[6..8]),
        g[8..16]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    )
}

/// GUID from the `#Pdb` stream of a portable PDB (ECMA-335 metadata root).
/// The symbol-server key appends a literal FFFFFFFF instead of an age.
fn portable_pdb_hash(f: &mut File) -> std::io::Result<Option<String>> {
    // The metadata root and stream headers sit at the start and are tiny.
    let mut buf = vec![0u8; 4096];
    f.seek(SeekFrom::Start(0))?;
    let n = read_up_to(f, &mut buf)?;
    buf.truncate(n);
    if buf.len() < 20 {
        return Ok(None);
    }
    let vlen = u32le(&buf[12..16]) as usize;
    if vlen > 256 || buf.len() < 16 + vlen + 4 {
        return Ok(None);
    }
    let mut off = 16 + vlen; // version string is stored pre-padded to 4
    let nstreams = u16le(&buf[off + 2..off + 4]) as usize;
    off += 4;
    if nstreams > 64 {
        return Ok(None);
    }
    for _ in 0..nstreams {
        if buf.len() < off + 8 {
            return Ok(None);
        }
        let soff = u32le(&buf[off..]) as u64;
        off += 8;
        let name_start = off;
        while off < buf.len() && buf[off] != 0 {
            off += 1;
            if off - name_start > 32 {
                return Ok(None);
            }
        }
        let name = &buf[name_start..off];
        off = (off + 1 + 3) & !3; // NUL, then pad to 4
        if name == b"#Pdb" {
            // PDB id: 16-byte GUID + 4-byte stamp.
            let mut pdb_id = [0u8; 20];
            if !read_exact_at(f, soff, &mut pdb_id)? {
                return Ok(None);
            }
            return Ok(Some(format!("{}FFFFFFFF", format_guid(&pdb_id[0..16]))));
        }
    }
    Ok(None)
}

/// Recursively collect identifiable files under `paths` (files are taken
/// as-is; directories are walked). Returns identified files and the paths
/// that were skipped as unrecognized.
pub fn collect(paths: &[std::path::PathBuf]) -> Result<(Vec<Candidate>, Vec<std::path::PathBuf>)> {
    let mut files = Vec::new();
    for p in paths {
        walk(p, &mut files)?;
    }
    let mut identified = Vec::new();
    let mut skipped = Vec::new();
    for path in files {
        match identify(&path) {
            Ok(Some((kind, hash))) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                identified.push(Candidate {
                    path,
                    name,
                    hash,
                    kind,
                });
            }
            Ok(None) => skipped.push(path),
            Err(e) => return Err(e),
        }
    }
    Ok((identified, skipped))
}

fn walk(path: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    let md = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
    if md.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    let rd = std::fs::read_dir(path).map_err(|e| Error::io(path, e))?;
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for entry in entries {
        walk(&entry, out)?;
    }
    Ok(())
}

/// A file identified for adding to the store.
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    /// Local path of the payload to ingest.
    pub path: std::path::PathBuf,
    /// File name as stored (first store path component).
    pub name: String,
    pub hash: String,
    pub kind: FileKind,
}
