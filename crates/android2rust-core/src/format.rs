use std::fmt::Write;

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.2} KB", b / KB)
    } else if b < GB {
        format!("{:.2} MB", b / MB)
    } else if b < TB {
        format!("{:.2} GB", b / GB)
    } else {
        format!("{:.2} TB", b / TB)
    }
}

pub fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0} ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.2} s")
    } else {
        let total = secs as u64;
        let mins = total / 60;
        let rem = secs - (mins as f64 * 60.0);
        if mins < 60 {
            format!("{mins}m {rem:.1}s")
        } else {
            let hrs = mins / 60;
            let rem_mins = mins % 60;
            format!("{hrs}h {rem_mins}m {rem:.0}s")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_hex_and_sizes() {
        assert_eq!(encode_hex_lower(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_duration(0.25), "250 ms");
    }
}
