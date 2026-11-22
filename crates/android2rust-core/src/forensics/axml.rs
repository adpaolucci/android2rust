use std::collections::BTreeSet;

#[derive(Debug, Clone, Default)]
pub(super) struct ManifestSecurityInfo {
    pub package: Option<String>,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub permissions: BTreeSet<String>,
}

const MAX_AXML_STRINGS: usize = 200_000;
const MAX_AXML_ATTRS: usize = 512;

pub(super) fn parse_manifest_security(bytes: &[u8]) -> ManifestSecurityInfo {
    if bytes.len() >= 8 && bytes.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
        parse_binary_axml(bytes)
    } else {
        parse_plaintext_manifest(bytes)
    }
}

pub(super) fn append_manifest_security(
    info: &ManifestSecurityInfo,
    metadata: &mut Vec<(String, String)>,
    warnings: &mut Vec<String>,
) {
    if let Some(pkg) = &info.package {
        metadata.push(("Package Name".to_string(), pkg.clone()));
    }
    if let Some(vn) = &info.version_name {
        metadata.push(("Version Name".to_string(), vn.clone()));
    }
    if let Some(vc) = &info.version_code {
        metadata.push(("Version Code".to_string(), vc.clone()));
    }
    if let Some(min) = &info.min_sdk {
        metadata.push(("Min SDK".to_string(), min.clone()));
    }
    if let Some(tgt) = &info.target_sdk {
        metadata.push(("Target SDK".to_string(), tgt.clone()));
    }
    if let Some(dbg) = info.debuggable {
        metadata.push(("Debuggable".to_string(), dbg.to_string()));
        if dbg {
            warnings.push(
                "Manifest sets android:debuggable=\"true\" — permits ADB debugging and JDWP attachment on release devices."
                    .to_string(),
            );
        }
    }
    if let Some(ab) = info.allow_backup {
        metadata.push(("Allow Backup".to_string(), ab.to_string()));
        if ab {
            warnings.push(
                "Manifest sets android:allowBackup=\"true\" — app data may be eligible for ADB backup extraction."
                    .to_string(),
            );
        }
    }
    if let Some(ct) = info.uses_cleartext_traffic {
        metadata.push(("Cleartext Traffic".to_string(), ct.to_string()));
        if ct {
            warnings.push(
                "Manifest sets android:usesCleartextTraffic=\"true\" — permits unencrypted HTTP network traffic."
                    .to_string(),
            );
        }
    }
}

fn parse_bool_str(s: &str) -> Option<bool> {
    let t = s.trim().to_ascii_lowercase();
    match t.as_str() {
        "true" | "1" | "-1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn record_tag_attr(info: &mut ManifestSecurityInfo, tag: &str, attr: &str, val: String) {
    match (tag, attr) {
        ("manifest", "package") if info.package.is_none() && !val.is_empty() => {
            info.package = Some(val);
        }
        ("manifest", "versionCode") if info.version_code.is_none() => {
            info.version_code = Some(val);
        }
        ("manifest", "versionName") if info.version_name.is_none() && !val.is_empty() => {
            info.version_name = Some(val);
        }
        ("uses-sdk", "minSdkVersion") if info.min_sdk.is_none() => {
            info.min_sdk = Some(val);
        }
        ("uses-sdk", "targetSdkVersion") if info.target_sdk.is_none() => {
            info.target_sdk = Some(val);
        }
        ("application", "debuggable") => {
            info.debuggable = parse_bool_str(&val);
        }
        ("application", "allowBackup") => {
            info.allow_backup = parse_bool_str(&val);
        }
        ("application", "usesCleartextTraffic") => {
            info.uses_cleartext_traffic = parse_bool_str(&val);
        }
        ("uses-permission" | "uses-permission-sdk-23", "name") if !val.is_empty() => {
            info.permissions.insert(val);
        }
        _ => {}
    }
}

fn parse_binary_axml(bytes: &[u8]) -> ManifestSecurityInfo {
    let mut info = ManifestSecurityInfo::default();
    let mut string_pool: Vec<String> = Vec::new();
    let mut res_ids: Vec<u32> = Vec::new();
    let mut pos = 8usize;

    while pos.saturating_add(8) <= bytes.len() {
        let ctype = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let hsize = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        let csize = u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]]) as usize;
        if csize < 8 {
            break;
        }
        let Some(end) = pos.checked_add(csize) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        let chunk = &bytes[pos..end];

        match ctype {
            0x0001 => {
                // RES_STRING_POOL_TYPE
                if chunk.len() >= 28 && hsize >= 28 {
                    let string_count =
                        (u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as usize).min(MAX_AXML_STRINGS);
                    let flags = u32::from_le_bytes([chunk[16], chunk[17], chunk[18], chunk[19]]);
                    let strings_start = u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]) as usize;
                    let is_utf8 = (flags & 0x0100) != 0;

                    string_pool.clear();
                    string_pool.reserve(string_count.min(4096));
                    for i in 0..string_count {
                        let off_pos = hsize.saturating_add(i.saturating_mul(4));
                        let Some(off_bytes) = chunk.get(off_pos..off_pos + 4) else {
                            break;
                        };
                        let rel_off =
                            u32::from_le_bytes([off_bytes[0], off_bytes[1], off_bytes[2], off_bytes[3]]) as usize;
                        let s_pos = strings_start.saturating_add(rel_off);
                        let decoded = if is_utf8 {
                            decode_pool_utf8(chunk, s_pos)
                        } else {
                            decode_pool_utf16(chunk, s_pos)
                        };
                        string_pool.push(decoded.unwrap_or_default());
                    }
                }
            }
            0x0180 => {
                // RES_XML_RESOURCE_MAP_TYPE
                let start = hsize.max(8);
                if start <= chunk.len() {
                    res_ids.clear();
                    for slot in chunk[start..].as_chunks::<4>().0 {
                        res_ids.push(u32::from_le_bytes(*slot));
                    }
                }
            }
            0x0102 if hsize <= chunk.len() && chunk.len() - hsize >= 20 => {
                // RES_XML_START_ELEMENT_TYPE
                let ext = &chunk[hsize..];
                let elem_idx = i32::from_le_bytes([ext[4], ext[5], ext[6], ext[7]]);
                let tag_name = usize::try_from(elem_idx)
                    .ok()
                    .and_then(|i| string_pool.get(i))
                    .map(String::as_str)
                    .unwrap_or("");
                let attr_start = u16::from_le_bytes([ext[8], ext[9]]) as usize;
                let attr_size = u16::from_le_bytes([ext[10], ext[11]]) as usize;
                let attr_count = (u16::from_le_bytes([ext[12], ext[13]]) as usize).min(MAX_AXML_ATTRS);

                if attr_size >= 20 {
                    for i in 0..attr_count {
                        let Some(aoff) = i.checked_mul(attr_size).and_then(|d| attr_start.checked_add(d)) else {
                            break;
                        };
                        let Some(attr_bytes) = ext.get(aoff..aoff + 20) else {
                            break;
                        };
                        let attr_name_idx =
                            i32::from_le_bytes([attr_bytes[4], attr_bytes[5], attr_bytes[6], attr_bytes[7]]);
                        let attr_res_id = usize::try_from(attr_name_idx)
                            .ok()
                            .and_then(|u| res_ids.get(u).copied());
                        let pool_attr_name = usize::try_from(attr_name_idx)
                            .ok()
                            .and_then(|u| string_pool.get(u))
                            .map(String::as_str)
                            .unwrap_or("");
                        let canonical_attr = match attr_res_id {
                            Some(0x0101_0003) => "name",
                            Some(0x0101_000f) => "debuggable",
                            Some(0x0101_020c) => "minSdkVersion",
                            Some(0x0101_021b) => "versionCode",
                            Some(0x0101_021c) => "versionName",
                            Some(0x0101_0270) => "targetSdkVersion",
                            Some(0x0101_0280) => "allowBackup",
                            Some(0x0101_04ec) => "usesCleartextTraffic",
                            _ => pool_attr_name,
                        };

                        let raw_val_idx =
                            i32::from_le_bytes([attr_bytes[8], attr_bytes[9], attr_bytes[10], attr_bytes[11]]);
                        let data_type = attr_bytes[15];
                        let data = u32::from_le_bytes([attr_bytes[16], attr_bytes[17], attr_bytes[18], attr_bytes[19]]);

                        let raw_val = usize::try_from(raw_val_idx)
                            .ok()
                            .and_then(|u| string_pool.get(u))
                            .filter(|s| !s.is_empty())
                            .cloned();
                        let resolved = raw_val.or_else(|| match data_type {
                            0x03 => string_pool.get(data as usize).cloned(),
                            0x10 => Some((data as i32).to_string()),
                            0x11 => Some(format!("0x{data:x}")),
                            0x12 => Some((data != 0).to_string()),
                            _ => None,
                        });

                        if let Some(val) = resolved {
                            record_tag_attr(&mut info, tag_name, canonical_attr, val);
                        }
                    }
                }
            }
            _ => {}
        }

        pos = end;
    }

    info
}

fn read_utf8_pool_len(chunk: &[u8], pos: &mut usize) -> Option<usize> {
    let b0 = *chunk.get(*pos)?;
    *pos += 1;
    if (b0 & 0x80) != 0 {
        let b1 = *chunk.get(*pos)?;
        *pos += 1;
        Some((usize::from(b0 & 0x7f) << 8) | usize::from(b1))
    } else {
        Some(usize::from(b0))
    }
}

fn decode_pool_utf8(chunk: &[u8], mut pos: usize) -> Option<String> {
    let _char_len = read_utf8_pool_len(chunk, &mut pos)?;
    let byte_len = read_utf8_pool_len(chunk, &mut pos)?;
    let raw = chunk.get(pos..pos.checked_add(byte_len)?)?;
    Some(String::from_utf8_lossy(raw).into_owned())
}

fn decode_pool_utf16(chunk: &[u8], mut pos: usize) -> Option<String> {
    let w0_bytes = chunk.get(pos..pos.checked_add(2)?)?;
    pos += 2;
    let w0 = u16::from_le_bytes([w0_bytes[0], w0_bytes[1]]);
    let char_len = if (w0 & 0x8000) != 0 {
        let w1_bytes = chunk.get(pos..pos.checked_add(2)?)?;
        pos += 2;
        let w1 = u16::from_le_bytes([w1_bytes[0], w1_bytes[1]]);
        (usize::from(w0 & 0x7fff) << 16) | usize::from(w1)
    } else {
        usize::from(w0)
    };
    let byte_len = char_len.checked_mul(2)?;
    let raw = chunk.get(pos..pos.checked_add(byte_len)?)?;
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    Some(String::from_utf16_lossy(&units))
}

fn parse_plaintext_manifest(bytes: &[u8]) -> ManifestSecurityInfo {
    let mut info = ManifestSecurityInfo::default();
    let text = String::from_utf8_lossy(bytes);

    if let Some(tag) = extract_tag_slice(&text, "<manifest") {
        if let Some(pkg) = super::extract_xml_attr(tag, "package") {
            record_tag_attr(&mut info, "manifest", "package", pkg);
        }
        if let Some(vc) =
            super::extract_xml_attr(tag, "android:versionCode").or_else(|| super::extract_xml_attr(tag, "versionCode"))
        {
            record_tag_attr(&mut info, "manifest", "versionCode", vc);
        }
        if let Some(vn) =
            super::extract_xml_attr(tag, "android:versionName").or_else(|| super::extract_xml_attr(tag, "versionName"))
        {
            record_tag_attr(&mut info, "manifest", "versionName", vn);
        }
    }
    if let Some(tag) = extract_tag_slice(&text, "<uses-sdk") {
        if let Some(min) = super::extract_xml_attr(tag, "android:minSdkVersion")
            .or_else(|| super::extract_xml_attr(tag, "minSdkVersion"))
        {
            record_tag_attr(&mut info, "uses-sdk", "minSdkVersion", min);
        }
        if let Some(tgt) = super::extract_xml_attr(tag, "android:targetSdkVersion")
            .or_else(|| super::extract_xml_attr(tag, "targetSdkVersion"))
        {
            record_tag_attr(&mut info, "uses-sdk", "targetSdkVersion", tgt);
        }
    }
    if let Some(tag) = extract_tag_slice(&text, "<application") {
        if let Some(v) =
            super::extract_xml_attr(tag, "android:debuggable").or_else(|| super::extract_xml_attr(tag, "debuggable"))
        {
            record_tag_attr(&mut info, "application", "debuggable", v);
        }
        if let Some(v) =
            super::extract_xml_attr(tag, "android:allowBackup").or_else(|| super::extract_xml_attr(tag, "allowBackup"))
        {
            record_tag_attr(&mut info, "application", "allowBackup", v);
        }
        if let Some(v) = super::extract_xml_attr(tag, "android:usesCleartextTraffic")
            .or_else(|| super::extract_xml_attr(tag, "usesCleartextTraffic"))
        {
            record_tag_attr(&mut info, "application", "usesCleartextTraffic", v);
        }
    }

    let mut idx = 0usize;
    while let Some(pos) = text[idx..].find("<uses-permission") {
        let start = idx + pos;
        let rest = &text[start..];
        let Some(end_rel) = rest.find('>') else {
            break;
        };
        let tag = &rest[..=end_rel];
        if let Some(perm) =
            super::extract_xml_attr(tag, "android:name").or_else(|| super::extract_xml_attr(tag, "name"))
        {
            record_tag_attr(&mut info, "uses-permission", "name", perm);
        }
        idx = start + end_rel + 1;
    }

    info
}

fn extract_tag_slice<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let start = text.find(marker)?;
    let rest = &text[start..];
    let end = rest.find('>')?;
    Some(&rest[..=end])
}
