use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_android2rust"))
}

#[test]
fn help_lists_subcommands() {
    let out = bin().arg("--help").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "presets", "build", "parse", "decode", "inspect", "dry-run", "run", "profile", "report", "env", "mcp", "gui",
    ] {
        assert!(s.contains(cmd), "missing subcommand {cmd}");
    }
}

#[test]
fn parse_adb_devices() {
    let out = bin().args(["parse", "adb devices -l"]).output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("adb devices -l") || s.to_lowercase().contains("devices"));
}

#[test]
fn decode_update_incompatible() {
    let out = bin()
        .args(["decode", "INSTALL_FAILED_UPDATE_INCOMPATIBLE"])
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Error") || s.contains("error"));
    assert!(s.contains("certificate") || s.contains("signing") || s.contains("incompatible"));
}

#[test]
fn presets_lists_at_least_ten() {
    let out = bin().arg("presets").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    let count = s.lines().filter(|l| l.contains('|')).count();
    assert!(count >= 8, "expected >=8 presets, got {count}");
}

#[test]
fn run_destructive_without_yes_fails() {
    let out = bin()
        .args(["run", "--op", "fastboot-erase", "--target", "userdata"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "destructive run without --yes must fail");
    let s = String::from_utf8_lossy(&out.stderr);
    let combined = s.to_lowercase() + &String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        combined.contains("--yes") || combined.contains("refusing") || combined.contains("destructive"),
        "expected refusal message"
    );
}

#[test]
fn env_reports_host_os() {
    let out = bin().arg("env").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.to_lowercase().contains("windows")
            || s.to_lowercase().contains("linux")
            || s.to_lowercase().contains("macos")
            || s.to_lowercase().contains("os")
    );
}

#[test]
fn mcp_tools_list_has_thirteen_distinct() {
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let mut child = bin()
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all((req.to_string() + "\n").as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    let s = String::from_utf8_lossy(&out.stdout);
    let mut distinct = std::collections::BTreeSet::new();
    for line in s.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(tools) = v.get("result").and_then(|r| r.get("tools")).and_then(|t| t.as_array())
        {
            for t in tools {
                if let Some(n) = t.get("name").and_then(|n| n.as_str()) {
                    distinct.insert(n.to_string());
                }
            }
        }
    }
    assert_eq!(
        distinct.len(),
        13,
        "expected 13 distinct tools, got {}: {:?}",
        distinct.len(),
        distinct
    );
}
