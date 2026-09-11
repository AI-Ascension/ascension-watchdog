#[cfg(not(windows))]
fn main() {
    #[cfg(target_os = "linux")]
    match ascension_watchdog::runtime::run_linux_helper_if_requested() {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("Linux launch helper failed: {error}");
            std::process::exit(1);
        }
    }
    std::process::exit(ascension_watchdog::cli::run(std::env::args()));
}

#[cfg(windows)]
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    match ascension_watchdog::windows_service::run_if_service(&args) {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => std::process::exit(ascension_watchdog::cli::run(args)),
        Err(error) => {
            eprintln!("Windows service entry failed: {error}");
            std::process::exit(1);
        }
    }
}
