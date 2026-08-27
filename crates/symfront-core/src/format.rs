//! Parsers for the text file formats used inside `000Admin/` and `refs.ptr`.
//!
//! These files are quoted-CSV-ish with CRLF line endings. Quoted fields do not
//! escape embedded quotes (symstore.exe never writes them), so we parse with a
//! simple state machine and keep raw text around for anything we don't
//! understand rather than failing hard.

use serde::Serialize;

use crate::TransactionId;

/// Split one record line into fields. A field is either bare (up to the next
/// comma) or double-quoted (quotes stripped, commas inside preserved).
pub fn split_fields(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut fields = Vec::new();
    let mut i = 0;
    loop {
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'"' {
            // Quoted field: scan to closing quote (no escape convention).
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'"' {
                end += 1;
            }
            fields.push(line[start..end].to_string());
            i = end + 1; // past closing quote
            // Skip to the comma separator (tolerate stray junk).
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            i += 1; // past comma
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            fields.push(line[start..i].to_string());
            i += 1; // past comma
        }
    }
    fields
}

/// Payload kind of an add transaction: real files or `file.ptr` pointers.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddPayloadKind {
    File,
    Ptr,
}

/// An `add` record from `history.txt` / `server.txt`.
#[derive(Clone, Debug, Serialize)]
pub struct AddRecord {
    pub id: TransactionId,
    pub kind: AddPayloadKind,
    /// MM/DD/YYYY as written by symstore.
    pub date: String,
    /// HH:MM:SS as written by symstore.
    pub time: String,
    pub product: String,
    pub version: String,
    pub comment: String,
}

/// A `del` record from `history.txt`.
#[derive(Clone, Debug, Serialize)]
pub struct DelRecord {
    pub id: TransactionId,
    /// Target transaction, if the field parsed as a number.
    pub target: Option<TransactionId>,
    /// The raw target field. symstore normally writes it zero-padded, but
    /// malformed records (e.g. `del,698`) exist in the wild.
    pub target_raw: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HistoryRecord {
    Add(AddRecord),
    Del(DelRecord),
    /// A line we could not interpret; preserved verbatim for diagnostics.
    Unknown { raw: String },
}

impl HistoryRecord {
    pub fn id(&self) -> Option<TransactionId> {
        match self {
            HistoryRecord::Add(a) => Some(a.id),
            HistoryRecord::Del(d) => Some(d.id),
            HistoryRecord::Unknown { .. } => None,
        }
    }
}

/// Parse one line of `history.txt` or `server.txt`.
pub fn parse_history_line(line: &str) -> HistoryRecord {
    let unknown = || HistoryRecord::Unknown {
        raw: line.to_string(),
    };
    let fields = split_fields(line);
    if fields.len() < 3 {
        return unknown();
    }
    let Ok(id) = fields[0].parse::<TransactionId>() else {
        return unknown();
    };
    match fields[1].as_str() {
        "add" => {
            if fields.len() < 8 {
                return unknown();
            }
            let kind = match fields[2].as_str() {
                "file" => AddPayloadKind::File,
                "ptr" => AddPayloadKind::Ptr,
                _ => return unknown(),
            };
            HistoryRecord::Add(AddRecord {
                id,
                kind,
                date: fields[3].clone(),
                time: fields[4].clone(),
                product: fields[5].clone(),
                version: fields[6].clone(),
                comment: fields[7].clone(),
            })
        }
        "del" => HistoryRecord::Del(DelRecord {
            id,
            target: fields[2].parse::<TransactionId>().ok(),
            target_raw: fields[2].clone(),
        }),
        _ => unknown(),
    }
}

/// One line of a transaction manifest (`000Admin/<id>`):
/// `"name\HASH","original source path"`.
#[derive(Clone, Debug, Serialize)]
pub struct TxEntry {
    /// Stored file name (first path component in the store), as recorded.
    pub name: String,
    /// Hash directory name (second component), as recorded (case matters on Linux).
    pub hash: String,
    /// Original source path the file was added from.
    pub source: String,
}

impl TxEntry {
    /// Store-relative directory (`name/HASH`) using the recorded case.
    pub fn rel_dir(&self) -> String {
        format!("{}/{}", self.name, self.hash)
    }

    /// Lower-cased key for case-insensitive joins.
    pub fn key(&self) -> (String, String) {
        (self.name.to_lowercase(), self.hash.to_lowercase())
    }
}

/// Parse one manifest line. Returns `None` for lines that don't match the
/// expected shape (caller records them as anomalies).
pub fn parse_tx_entry(line: &str) -> Option<TxEntry> {
    let fields = split_fields(line);
    if fields.len() < 2 {
        return None;
    }
    let (name, hash) = fields[0].rsplit_once('\\')?;
    if name.is_empty() || hash.is_empty() || name.contains('\\') {
        return None;
    }
    Some(TxEntry {
        name: name.to_string(),
        hash: hash.to_string(),
        source: fields[1].clone(),
    })
}

/// One line of a `refs.ptr` file:
/// `0000000237,file,"C:\src\path",bin,,N,,` — we only interpret the leading
/// transaction id and keep the raw line for faithful rewrites.
#[derive(Clone, Debug, Serialize)]
pub struct RefLine {
    pub tx: Option<TransactionId>,
    pub raw: String,
}

pub fn parse_ref_line(line: &str) -> RefLine {
    let first = line.split(',').next().unwrap_or("");
    RefLine {
        tx: first.parse::<TransactionId>().ok(),
        raw: line.to_string(),
    }
}

/// Split text into logical lines, tolerating CRLF, LF, and an unterminated
/// final line (all of which occur in real stores). Empty lines are skipped.
pub fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.trim().is_empty())
}

/// Compressed-payload name: last character replaced with `_` (CAB convention),
/// e.g. `foo.exe` -> `foo.ex_`.
pub fn compressed_name(name: &str) -> String {
    let mut s: Vec<char> = name.chars().collect();
    if let Some(last) = s.last_mut() {
        *last = '_';
    }
    s.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_quoted() {
        let f = split_fields(r#"0000000001,add,file,01/31/2025,07:36:53,"Darwinia <= 2.3.3-761","","","#);
        assert_eq!(f[0], "0000000001");
        assert_eq!(f[5], "Darwinia <= 2.3.3-761");
        assert_eq!(f[6], "");
    }

    #[test]
    fn quoted_with_comma() {
        let f = split_fields(r#""a, b","c""#);
        assert_eq!(f, vec!["a, b", "c"]);
    }

    #[test]
    fn parse_add() {
        let r = parse_history_line(r#"0000000718,add,file,08/27/2026,01:16:11,"LLVM","23.1.0-rc3","","#);
        match r {
            HistoryRecord::Add(a) => {
                assert_eq!(a.id, TransactionId(718));
                assert_eq!(a.product, "LLVM");
                assert_eq!(a.kind, AddPayloadKind::File);
            }
            _ => panic!("expected add"),
        }
    }

    #[test]
    fn parse_del_padded_and_not() {
        match parse_history_line("0000000185,del,0000000184") {
            HistoryRecord::Del(d) => {
                assert_eq!(d.target, Some(TransactionId(184)));
                assert_eq!(d.target_raw, "0000000184");
            }
            _ => panic!(),
        }
        match parse_history_line("0000000699,del,698") {
            HistoryRecord::Del(d) => {
                assert_eq!(d.target, Some(TransactionId(698)));
                assert_eq!(d.target_raw, "698");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_entry() {
        let e = parse_tx_entry(r#""clang-cl.exe\316AFF9178d9000","C:\LLVM\23.1.0\bin\clang-cl.exe""#)
            .unwrap();
        assert_eq!(e.name, "clang-cl.exe");
        assert_eq!(e.hash, "316AFF9178d9000");
        assert_eq!(e.source, r"C:\LLVM\23.1.0\bin\clang-cl.exe");
        assert_eq!(e.rel_dir(), "clang-cl.exe/316AFF9178d9000");
    }

    #[test]
    fn ref_line() {
        let r = parse_ref_line(r#"0000000237,file,"C:\x\7zr.exe",bin,,N,,"#);
        assert_eq!(r.tx, Some(TransactionId(237)));
    }

    #[test]
    fn unterminated_final_line() {
        let text = "a\r\nb\r\nc";
        assert_eq!(lines(text).collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }

    #[test]
    fn compressed() {
        assert_eq!(compressed_name("7zr.exe"), "7zr.ex_");
        assert_eq!(compressed_name("foo.pdb"), "foo.pd_");
    }
}
