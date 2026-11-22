#![forbid(unsafe_code)]

fn main() {
    let _ = android2rust_core::logging::init_logging("warn", None);
    if let Err(e) = android2rust_mcp::run_stdio_server() {
        eprintln!("android2rust-mcp fatal error: {e}");
        std::process::exit(1);
    }
}
