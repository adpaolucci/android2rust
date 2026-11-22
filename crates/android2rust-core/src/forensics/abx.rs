use super::{
    ArtifactKind, ForensicEntry, ForensicReport, TimelineEvent, collect_permissions_from_str, encode_hex_lower,
    epoch_ms_to_rfc3339,
};
use crate::model::ForensicOptions;
use std::collections::BTreeSet;
use std::path::Path;

const MAX_ABX_INTERNED: usize = 65_535;
const MAX_ABX_TOKENS: usize = 200_000;
const MAX_ABX_DEPTH: usize = 128;

struct AbxCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    interned: Vec<String>,
}

impl<'a> AbxCursor<'a> {
    fn new(buf: &'a [u8], start: usize) -> Self {
        Self {
            buf,
            pos: start,
            interned: Vec::new(),
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let s = self.buf.get(self.pos..self.pos.checked_add(2)?)?;
        self.pos += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let s = self.buf.get(self.pos..self.pos.checked_add(4)?)?;
        self.pos += 4;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_i32(&mut self) -> Option<i32> {
        self.read_u32().map(|v| v as i32)
    }

    fn read_u64(&mut self) -> Option<u64> {
        let s = self.buf.get(self.pos..self.pos.checked_add(8)?)?;
        self.pos += 8;
        Some(u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }

    fn read_i64(&mut self) -> Option<i64> {
        self.read_u64().map(|v| v as i64)
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn read_utf8_len_u16(&mut self) -> Option<String> {
        let len = usize::from(self.read_u16()?);
        let raw = self.read_bytes(len)?;
        Some(String::from_utf8_lossy(raw).into_owned())
    }

    fn read_interned(&mut self) -> Option<String> {
        let idx = self.read_u16()?;
        if idx == 0xFFFF {
            let s = self.read_utf8_len_u16()?;
            if self.interned.len() < MAX_ABX_INTERNED {
                self.interned.push(s.clone());
            }
            Some(s)
        } else {
            self.interned.get(usize::from(idx)).cloned()
        }
    }

    fn decode_typed_value(&mut self, dtype: u8) -> Option<(String, Option<i64>)> {
        match dtype {
            0x10 => Some(("null".to_string(), None)),
            0x20 => Some((self.read_utf8_len_u16()?, None)),
            0x30 => Some((self.read_interned()?, None)),
            0x40 => {
                let len = usize::from(self.read_u16()?);
                let raw = self.read_bytes(len)?;
                let hex = encode_hex_lower(&raw[..raw.len().min(64)]);
                let s = if raw.len() > 64 {
                    format!("{hex}... ({} B)", raw.len())
                } else {
                    hex
                };
                Some((s, None))
            }
            0x50 => {
                let len = usize::from(self.read_u16()?);
                let raw = self.read_bytes(len)?;
                let hex = encode_hex_lower(&raw[..raw.len().min(32)]);
                Some((format!("base64-bytes({} B): {hex}", raw.len()), None))
            }
            0x60 => Some((self.read_i32()?.to_string(), None)),
            0x70 => Some((format!("0x{:x}", self.read_u32()?), None)),
            0x80 => {
                let v = self.read_i64()?;
                Some((v.to_string(), Some(v)))
            }
            0x90 => Some((format!("0x{:x}", self.read_u64()?), None)),
            0xA0 => Some((f32::from_bits(self.read_u32()?).to_string(), None)),
            0xB0 => Some((f64::from_bits(self.read_u64()?).to_string(), None)),
            0xC0 => Some(("true".to_string(), None)),
            0xD0 => Some(("false".to_string(), None)),
            _ => None,
        }
    }
}

pub(super) fn inspect_abx_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let mut entries = Vec::new();
    let mut permissions = BTreeSet::new();
    let mut timeline = Vec::new();
    let mut warnings = Vec::new();

    let mut cur = AbxCursor::new(bytes, 4);
    let mut tag_stack: Vec<String> = Vec::new();
    let mut element_count = 0usize;
    let mut attr_count = 0usize;
    let mut tokens = 0usize;

    while cur.pos < bytes.len() && tokens < MAX_ABX_TOKENS {
        let Some(tok) = cur.read_u8() else {
            break;
        };
        tokens += 1;
        let event = tok & 0x0f;
        let dtype = tok & 0xf0;

        match event {
            0 => {}     // START_DOCUMENT
            1 => break, // END_DOCUMENT
            2 => {
                // START_TAG
                let Some(tag) = cur.read_interned() else {
                    warnings.push(format!(
                        "Truncated or invalid ABX START_TAG at byte offset {}.",
                        cur.pos
                    ));
                    break;
                };
                if tag_stack.len() >= MAX_ABX_DEPTH {
                    warnings.push(format!(
                        "ABX element nesting exceeded safety cap ({MAX_ABX_DEPTH} levels); stopping parse safely."
                    ));
                    break;
                }
                element_count += 1;
                tag_stack.push(tag.clone());
                if entries.len() < opts.max_entries {
                    let elem_path = tag_stack.join("/");
                    entries.push(ForensicEntry {
                        category: "ABX Element".to_string(),
                        name: elem_path,
                        detail: format!("<{tag}>"),
                        size_bytes: None,
                    });
                }
            }
            3 => {
                // END_TAG
                if cur.read_interned().is_none() {
                    warnings.push(format!("Truncated or invalid ABX END_TAG at byte offset {}.", cur.pos));
                    break;
                }
                let _ = tag_stack.pop();
            }
            15 => {
                // ATTRIBUTE (0x0F)
                let Some(attr_name) = cur.read_interned() else {
                    warnings.push(format!(
                        "Truncated or invalid ABX ATTRIBUTE name at byte offset {}.",
                        cur.pos
                    ));
                    break;
                };
                let Some((val_str, long_val)) = cur.decode_typed_value(dtype) else {
                    warnings.push(format!(
                        "Unsupported or truncated ABX value type 0x{dtype:02x} for attribute '{attr_name}' at offset {}.",
                        cur.pos
                    ));
                    break;
                };
                attr_count += 1;
                let elem_path = if tag_stack.is_empty() {
                    "<root>".to_string()
                } else {
                    tag_stack.join("/")
                };
                let full_name = format!("{elem_path}@{attr_name}");
                if opts.extract_manifest_permissions {
                    collect_permissions_from_str(&val_str, &mut permissions);
                }
                if let Some(ms) = long_val
                    && let Some(ts) = epoch_ms_to_rfc3339(ms)
                {
                    timeline.push(TimelineEvent {
                        timestamp: ts,
                        source: "ABX".to_string(),
                        category: "ABX Timestamp".to_string(),
                        target: full_name.clone(),
                        detail: val_str.clone(),
                    });
                }
                if entries.len() < opts.max_entries {
                    entries.push(ForensicEntry {
                        category: "ABX Attribute".to_string(),
                        name: full_name,
                        detail: val_str,
                        size_bytes: None,
                    });
                }
            }
            4..=10 => {
                // TEXT (4), CDSECT (5), ENTITY_REF (6), IGNORABLE_WHITESPACE (7), PI (8), COMMENT (9), DOCDECL (10)
                let Some((txt, _)) = cur.decode_typed_value(dtype) else {
                    warnings.push(format!(
                        "Unsupported or truncated ABX event {event} (type 0x{dtype:02x}) at offset {}.",
                        cur.pos
                    ));
                    break;
                };
                if event == 4 {
                    let trimmed = txt.trim();
                    if !trimmed.is_empty() {
                        if opts.extract_manifest_permissions {
                            collect_permissions_from_str(trimmed, &mut permissions);
                        }
                        if entries.len() < opts.max_entries {
                            let elem_path = if tag_stack.is_empty() {
                                "<root>".to_string()
                            } else {
                                tag_stack.join("/")
                            };
                            entries.push(ForensicEntry {
                                category: "ABX Text".to_string(),
                                name: elem_path,
                                detail: trimmed.to_string(),
                                size_bytes: None,
                            });
                        }
                    }
                }
            }
            other => {
                warnings.push(format!(
                    "Unknown ABX event nibble 0x{other:02x} at offset {}; stopping parse safely.",
                    cur.pos.saturating_sub(1)
                ));
                break;
            }
        }
    }

    if tokens >= MAX_ABX_TOKENS && cur.pos < bytes.len() {
        warnings.push(format!(
            "ABX token stream exceeded safety cap ({MAX_ABX_TOKENS} tokens); truncated remaining bytes."
        ));
    }

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::AndroidBinaryXml,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata: vec![
            (
                "ABX Protocol Version".to_string(),
                "0 (Android 12+ Binary XML)".to_string(),
            ),
            ("Elements Parsed".to_string(), element_count.to_string()),
            ("Attributes Extracted".to_string(), attr_count.to_string()),
            ("Interned Strings".to_string(), cur.interned.len().to_string()),
            ("Permissions Found".to_string(), permissions.len().to_string()),
            ("Timeline Events".to_string(), timeline.len().to_string()),
        ],
        permissions_or_tables: permissions.into_iter().collect(),
        entries,
        warnings,
        timeline,
    }
}
