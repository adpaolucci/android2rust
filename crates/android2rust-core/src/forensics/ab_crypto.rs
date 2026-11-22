use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Upper iteration bound to protect against CPU DoS from forged `.ab` encryption headers.
pub const MAX_PBKDF2_ROUNDS: u32 = 2_000_000;

#[derive(Debug, Clone)]
pub(super) struct AbEncryptionHeader {
    pub user_salt: Vec<u8>,
    pub checksum_salt: Vec<u8>,
    pub rounds: u32,
    pub user_iv: Vec<u8>,
    pub master_key_blob: Vec<u8>,
    pub payload_offset: usize,
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    let s = raw.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("Odd hex length ({}) in .ab encryption header.", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0]).ok_or_else(|| "Invalid hex digit in .ab encryption header.".to_string())?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| "Invalid hex digit in .ab encryption header.".to_string())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Replicates AOSP `PasswordUtils.makeKeyChecksum` byte-to-char sign extension followed by UTF-8 encoding.
fn encode_aosp_utf8_byte_chars(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() * 3);
    for &b in raw {
        let signed = (b as i8) as i16 as u16;
        if let Some(ch) = char::from_u32(u32::from(signed)) {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            out.extend_from_slice(s.as_bytes());
        }
    }
    out
}

/// Replicates Android Oreo `PBKDF2WithHmacSHA1` replacement-character quirk where high bytes became U+FFFD.
fn encode_aosp_replacement_utf8(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() * 3);
    for &b in raw {
        if b < 0x80 {
            out.push(b);
        } else {
            out.extend_from_slice(&[0xEF, 0xBF, 0xBD]);
        }
    }
    out
}

fn encode_low8bit_password(password: &str) -> Vec<u8> {
    password.chars().map(|c| (c as u32 & 0xff) as u8).collect()
}

pub(super) fn parse_ab_encryption_header(bytes: &[u8], mut pos: usize) -> Result<AbEncryptionHeader, String> {
    let mut hdr_lines = Vec::with_capacity(5);
    for _ in 0..5 {
        let Some(nl) = bytes.get(pos..).and_then(|s| s.iter().position(|&b| b == b'\n')) else {
            return Err("Truncated encrypted .ab header (expected 5 encryption metadata lines).".to_string());
        };
        let line = String::from_utf8_lossy(&bytes[pos..pos + nl]).trim().to_string();
        hdr_lines.push(line);
        pos += nl + 1;
    }

    let user_salt = decode_hex(&hdr_lines[0])?;
    let checksum_salt = decode_hex(&hdr_lines[1])?;
    let rounds: u32 = hdr_lines[2]
        .parse()
        .map_err(|_| format!("Invalid PBKDF2 rounds value '{}' in .ab header.", hdr_lines[2]))?;
    let user_iv = decode_hex(&hdr_lines[3])?;
    let master_key_blob = decode_hex(&hdr_lines[4])?;

    if user_salt.is_empty() || checksum_salt.is_empty() || user_iv.is_empty() || master_key_blob.is_empty() {
        return Err("Encrypted .ab header contains empty salt, IV, or master key blob.".to_string());
    }

    Ok(AbEncryptionHeader {
        user_salt,
        checksum_salt,
        rounds,
        user_iv,
        master_key_blob,
        payload_offset: pos,
    })
}

fn try_unwrap_master_key_blob(
    version: &str,
    hdr: &AbEncryptionHeader,
    password_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let user_iv: [u8; 16] = hdr.user_iv.as_slice().try_into().map_err(|_| {
        format!(
            "Expected 16-byte user IV in .ab header, got {} bytes.",
            hdr.user_iv.len()
        )
    })?;

    let user_key = pbkdf2_hmac_array::<Sha1, 32>(password_bytes, &hdr.user_salt, hdr.rounds);
    let mut blob_buf = hdr.master_key_blob.clone();
    let plain_blob = Aes256CbcDec::new(&user_key.into(), &user_iv.into())
        .decrypt_padded::<Pkcs7>(&mut blob_buf)
        .map_err(|_| "Incorrect .ab backup password (master key blob decryption failed).".to_string())?;

    let mut cur = 0usize;
    let iv_len = usize::from(*plain_blob.get(cur).ok_or("Malformed .ab master key blob.")?);
    cur += 1;
    let master_iv = plain_blob
        .get(cur..cur.saturating_add(iv_len))
        .ok_or("Truncated master IV inside .ab master key blob.")?
        .to_vec();
    cur += iv_len;

    let mk_len = usize::from(
        *plain_blob
            .get(cur)
            .ok_or("Truncated master key length inside .ab blob.")?,
    );
    cur += 1;
    let master_key = plain_blob
        .get(cur..cur.saturating_add(mk_len))
        .ok_or("Truncated master key inside .ab master key blob.")?
        .to_vec();
    cur += mk_len;

    let ck_len = usize::from(
        *plain_blob
            .get(cur)
            .ok_or("Truncated checksum length inside .ab blob.")?,
    );
    cur += 1;
    let expected_checksum = plain_blob
        .get(cur..cur.saturating_add(ck_len))
        .ok_or("Truncated checksum inside .ab master key blob.")?;

    let utf8_aosp = encode_aosp_utf8_byte_chars(&master_key);
    let ck_aosp_utf8 = pbkdf2_hmac_array::<Sha1, 32>(&utf8_aosp, &hdr.checksum_salt, hdr.rounds);
    if ct_eq(&ck_aosp_utf8, expected_checksum) {
        return Ok((master_iv, master_key));
    }

    let repl_aosp = encode_aosp_replacement_utf8(&master_key);
    let ck_repl = pbkdf2_hmac_array::<Sha1, 32>(&repl_aosp, &hdr.checksum_salt, hdr.rounds);
    if ct_eq(&ck_repl, expected_checksum) {
        return Ok((master_iv, master_key));
    }

    let ck_raw = pbkdf2_hmac_array::<Sha1, 32>(&master_key, &hdr.checksum_salt, hdr.rounds);
    if (version == "1" || !master_key.is_empty()) && ct_eq(&ck_raw, expected_checksum) {
        return Ok((master_iv, master_key));
    }

    Err("Incorrect .ab backup password (master key checksum mismatch).".to_string())
}

pub(super) fn decrypt_ab_payload(
    version: &str,
    hdr: &AbEncryptionHeader,
    ciphertext: &[u8],
    password: &str,
    max_ciphertext_bytes: usize,
) -> Result<Vec<u8>, String> {
    if hdr.rounds == 0 || hdr.rounds > MAX_PBKDF2_ROUNDS {
        return Err(format!(
            ".ab header declares {} PBKDF2 rounds (outside safe range 1..={MAX_PBKDF2_ROUNDS}); refusing decryption.",
            hdr.rounds
        ));
    }
    if hdr.master_key_blob.is_empty() || !hdr.master_key_blob.len().is_multiple_of(16) {
        return Err("Encrypted .ab master key blob length is invalid for AES-256-CBC.".to_string());
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err("Encrypted .ab payload is empty or truncated mid-block (not a multiple of 16 bytes).".to_string());
    }
    if ciphertext.len() > max_ciphertext_bytes {
        return Err(format!(
            "Encrypted .ab payload ({} bytes) exceeds bounded {} MiB decryption buffer.",
            ciphertext.len(),
            max_ciphertext_bytes / (1024 * 1024)
        ));
    }

    let (master_iv, master_key) = match try_unwrap_master_key_blob(version, hdr, password.as_bytes()) {
        Ok(pair) => pair,
        Err(first_err) => {
            let low8 = encode_low8bit_password(password);
            if low8 != password.as_bytes() {
                try_unwrap_master_key_blob(version, hdr, &low8).map_err(|_| first_err)?
            } else {
                return Err(first_err);
            }
        }
    };

    let miv_arr: [u8; 16] = master_iv
        .as_slice()
        .try_into()
        .map_err(|_| format!("Invalid decrypted master IV length {} (expected 16).", master_iv.len()))?;
    let mk_arr: [u8; 32] = master_key.as_slice().try_into().map_err(|_| {
        format!(
            "Invalid decrypted master key length {} (expected 32).",
            master_key.len()
        )
    })?;

    let mut ct_buf = ciphertext.to_vec();
    let plain = Aes256CbcDec::new(&mk_arr.into(), &miv_arr.into())
        .decrypt_padded::<Pkcs7>(&mut ct_buf)
        .map_err(|_| "Failed to AES-256-CBC decrypt .ab backup payload (corrupt ciphertext).".to_string())?;

    Ok(plain.to_vec())
}

#[cfg(test)]
pub(super) fn encrypt_ab_v5_for_test(plaintext: &[u8], password: &str, rounds: u32, seed: &[u8]) -> Vec<u8> {
    use aes::cipher::BlockModeEncrypt;
    use sha2::{Digest, Sha512};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let derive64 = |label: &[u8]| -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(seed);
        h.update(label);
        h.finalize().into()
    };

    let user_salt = derive64(b":user_salt");
    let checksum_salt = derive64(b":checksum_salt");
    let iv_digest = derive64(b":ivs");
    let user_iv: [u8; 16] = iv_digest[0..16].try_into().unwrap();
    let master_iv: [u8; 16] = iv_digest[16..32].try_into().unwrap();

    // Ensure at least one byte >= 0x80 so AOSP sign-extended byte-to-char UTF-8 checksum behavior is exercised
    let master_key: [u8; 32] = (0u8..=255)
        .map(|counter| {
            let mut h = Sha512::new();
            h.update(seed);
            h.update(b":master_key:");
            h.update([counter]);
            let digest: [u8; 64] = h.finalize().into();
            let key: [u8; 32] = digest[..32].try_into().unwrap();
            key
        })
        .find(|k| k.iter().any(|&b| b >= 0x80))
        .unwrap_or_else(|| derive64(b":master_fallback")[..32].try_into().unwrap());

    let user_key = pbkdf2_hmac_array::<Sha1, 32>(password.as_bytes(), &user_salt, rounds);
    let mk_utf8 = encode_aosp_utf8_byte_chars(&master_key);
    let checksum = pbkdf2_hmac_array::<Sha1, 32>(&mk_utf8, &checksum_salt, rounds);

    let mut blob_plain = Vec::new();
    blob_plain.push(master_iv.len() as u8);
    blob_plain.extend_from_slice(&master_iv);
    blob_plain.push(master_key.len() as u8);
    blob_plain.extend_from_slice(&master_key);
    blob_plain.push(checksum.len() as u8);
    blob_plain.extend_from_slice(&checksum);

    let mut blob_buf = blob_plain.clone();
    blob_buf.resize(blob_plain.len() + 16, 0);
    let blob_ct = Aes256CbcEnc::new(&user_key.into(), &user_iv.into())
        .encrypt_padded::<Pkcs7>(&mut blob_buf, blob_plain.len())
        .unwrap()
        .to_vec();

    let mut payload_buf = plaintext.to_vec();
    payload_buf.resize(plaintext.len() + 16, 0);
    let payload_ct = Aes256CbcEnc::new(&master_key.into(), &master_iv.into())
        .encrypt_padded::<Pkcs7>(&mut payload_buf, plaintext.len())
        .unwrap()
        .to_vec();

    let mut ab = Vec::new();
    ab.extend_from_slice(b"ANDROID BACKUP\n5\n1\nAES-256\n");
    ab.extend_from_slice(crate::format::encode_hex_lower(&user_salt).as_bytes());
    ab.push(b'\n');
    ab.extend_from_slice(crate::format::encode_hex_lower(&checksum_salt).as_bytes());
    ab.push(b'\n');
    ab.extend_from_slice(rounds.to_string().as_bytes());
    ab.push(b'\n');
    ab.extend_from_slice(crate::format::encode_hex_lower(&user_iv).as_bytes());
    ab.push(b'\n');
    ab.extend_from_slice(crate::format::encode_hex_lower(&blob_ct).as_bytes());
    ab.push(b'\n');
    ab.extend_from_slice(&payload_ct);
    ab
}
