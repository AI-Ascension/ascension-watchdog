//! Test-only executable synthetic recovery host.

use std::net::SocketAddr;
use std::path::PathBuf;

use fault_fixture::{FaultPoint, ServerConfig, run_server};

fn main() {
    if let Err(error) = run() {
        eprintln!("fault-fixture-server: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut database: Option<PathBuf> = None;
    let mut port = 0_u16;
    let mut fault = FaultPoint::None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--db" => database = arguments.next().map(PathBuf::from),
            "--port" => {
                let value = arguments.next().ok_or("--port requires a value")?;
                port = value.parse::<u16>()?;
            }
            "--fault" => {
                let value = arguments.next().ok_or("--fault requires a value")?;
                fault = FaultPoint::parse(&value).ok_or("unknown fault point")?;
            }
            "--help" => {
                println!("fault-fixture-server --db PATH [--port PORT] [--fault POINT]");
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let database = database.ok_or("--db is required")?;
    let bind = SocketAddr::from(([127, 0, 0, 1], port));
    run_server(&ServerConfig {
        database,
        bind,
        fault,
    })?;
    Ok(())
}
