#[cfg(target_os = "linux")]
fn main() {
    let mut socket = None;
    let mut policy = None;
    let mut ledger = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => socket = arguments.next(),
            "--policy" => policy = arguments.next(),
            "--ledger" => ledger = arguments.next(),
            "--help" | "-h" => {
                println!(
                    "linux-systemd-broker --socket ABSOLUTE_SOCKET --policy ROOT_OWNED_JSON --ledger ROOT_OWNED_LEDGER"
                );
                return;
            }
            _ if argument.strip_prefix("--socket=").is_some() => {
                socket = argument.strip_prefix("--socket=").map(str::to_owned);
            }
            _ if argument.strip_prefix("--policy=").is_some() => {
                policy = argument.strip_prefix("--policy=").map(str::to_owned);
            }
            _ if argument.strip_prefix("--ledger=").is_some() => {
                ledger = argument.strip_prefix("--ledger=").map(str::to_owned);
            }
            _ => {
                eprintln!("linux-systemd-broker: unknown or incomplete argument");
                std::process::exit(2);
            }
        }
    }
    let Some(socket) = socket else {
        eprintln!("linux-systemd-broker: --socket is required");
        std::process::exit(2);
    };
    let Some(policy) = policy else {
        eprintln!("linux-systemd-broker: --policy is required");
        std::process::exit(2);
    };
    let Some(ledger) = ledger else {
        eprintln!("linux-systemd-broker: --ledger is required");
        std::process::exit(2);
    };
    if let Err(error) = ascension_watchdog::platform::linux_broker::run_native_broker(
        std::path::Path::new(&socket),
        std::path::Path::new(&policy),
        std::path::Path::new(&ledger),
    ) {
        eprintln!("linux-systemd-broker: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux-systemd-broker is only available on Linux");
    std::process::exit(1);
}
