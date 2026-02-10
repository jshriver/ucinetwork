// server.rs
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    engine: String,
    bind_address: String, // e.g., "0.0.0.0:6242" to listen on all interfaces
}

fn main() {
    // Parse command line arguments for --config
    let args: Vec<String> = std::env::args().collect();
    let config_file = parse_config_arg(&args).unwrap_or_else(|| "server.json".to_string());

    // Load config file
    let cfg_data = fs::read_to_string(&config_file)
        .expect(&format!("failed to read {}", config_file));
    let cfg: Config = serde_json::from_str(&cfg_data)
        .expect("failed to parse config");

    // Get external IP address
    println!("Detecting external IP address...");
    match get_external_ip() {
        Ok(ip) => println!("External IP: {}", ip),
        Err(e) => eprintln!("Failed to get external IP: {}", e),
    }

    // Bind to TCP port
    let listener = TcpListener::bind(&cfg.bind_address)
        .expect(&format!("failed to bind to {}", cfg.bind_address));
    
    println!("Server listening on {}", cfg.bind_address);
    println!("Clients should connect to: <external_ip>:6242");
    println!("Waiting for connections...");

    // Accept connections (one at a time for now)
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("Client connected: {}", stream.peer_addr().unwrap());
                handle_client(stream, &cfg);
                println!("Client disconnected");
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

fn get_external_ip() -> Result<String, Box<dyn std::error::Error>> {
    // Try multiple services in case one is down
    let services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ];

    for service in &services {
        match try_ip_service(service) {
            Ok(ip) => return Ok(ip.trim().to_string()),
            Err(_) => continue,
        }
    }

    Err("All IP lookup services failed".into())
}

fn try_ip_service(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Try using curl first (most likely to be available)
    if let Ok(output) = Command::new("curl")
        .arg("-s")
        .arg("-4") // Force IPv4
        .arg("--max-time")
        .arg("5")
        .arg(url)
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try wget as fallback
    if let Ok(output) = Command::new("wget")
        .arg("-qO-")
        .arg("--timeout=5")
        .arg(url)
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try PowerShell on Windows
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .arg("-Command")
            .arg(format!("(Invoke-WebRequest -Uri {} -UseBasicParsing -TimeoutSec 5).Content", url))
            .output()
        {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
    }

    Err("Failed to fetch IP".into())
}

fn handle_client(stream: TcpStream, cfg: &Config) {
    // Spawn engine with platform-specific settings
    let mut cmd = Command::new(&cfg.engine);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    // Windows-specific: hide console window
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().expect("failed to spawn engine");

    let mut engine_stdin = child.stdin.take().expect("engine stdin");
    let mut engine_stdout = child.stdout.take().expect("engine stdout");

    // Clone the stream for bidirectional communication
    let mut read_stream = stream.try_clone().expect("failed to clone stream");
    let mut write_stream = stream;

    // Thread: network -> engine stdin
    let stdin_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = match read_stream.read(&mut buf) {
                Ok(0) => break, // Connection closed
                Ok(n) => n,
                Err(_) => break,
            };
            if engine_stdin.write_all(&buf[..n]).is_err() {
                break;
            }
            let _ = engine_stdin.flush();
        }
    });

    // Thread: engine stdout -> network
    let stdout_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = match engine_stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if write_stream.write_all(&buf[..n]).is_err() {
                break;
            }
            let _ = write_stream.flush();
        }
    });

    let _ = stdin_thread.join();
    let _ = stdout_thread.join();
    let _ = child.kill(); // Ensure engine is terminated
    let _ = child.wait();
}

fn parse_config_arg(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}