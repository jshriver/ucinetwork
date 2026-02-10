// client.rs
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, Shutdown};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    server_address: String, // e.g., "192.168.1.100:6242"
    logfile: String,
    enable_logging: bool,
}

fn main() {
    // Parse command line arguments for --config
    let args: Vec<String> = std::env::args().collect();
    let config_file = parse_config_arg(&args).unwrap_or_else(|| "client.json".to_string());

    // Load config file
    let cfg_data = fs::read_to_string(&config_file)
        .expect(&format!("failed to read {}", config_file));
    let cfg: Config = serde_json::from_str(&cfg_data)
        .expect("failed to parse config");

    // Open log file only if logging is enabled
    let logfile = if cfg.enable_logging {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&cfg.logfile)
                .expect("failed to open logfile")
        )))
    } else {
        None
    };

    // Connect to server
    eprintln!("Connecting to server at {}...", cfg.server_address);
    let stream = TcpStream::connect(&cfg.server_address)
        .expect(&format!("failed to connect to {}", cfg.server_address));
    
    // Set read timeout to allow periodic checking for shutdown
    stream.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("failed to set read timeout");
    
    eprintln!("Connected to server at {}", cfg.server_address);
    if cfg.enable_logging {
        eprintln!("Logging enabled: {}", cfg.logfile);
    }

    // Shutdown flag shared between threads
    let shutdown = Arc::new(AtomicBool::new(false));

    // Clone the stream for bidirectional communication
    let mut read_stream = stream.try_clone().expect("failed to clone stream");
    let mut write_stream = stream.try_clone().expect("failed to clone stream");
    let shutdown_stream = stream.try_clone().expect("failed to clone stream");

    // Thread: stdin -> network
    let log_in = logfile.clone();
    let shutdown_flag = Arc::clone(&shutdown);
    let stdin_thread = thread::spawn(move || {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let line_with_newline = format!("{}\n", line);
                    let bytes = line_with_newline.as_bytes();
                    
                    if write_stream.write_all(bytes).is_err() {
                        break;
                    }
                    let _ = write_stream.flush();
                    
                    // Log outgoing data (to server) if logging is enabled
                    if let Some(ref log) = log_in {
                        if let Ok(mut log) = log.lock() {
                            let _ = log.write_all(b">> ");
                            let _ = log.write_all(bytes);
                            let _ = log.flush();
                        }
                    }
                    
                    // Check if the line is "quit" and exit
                    if line.trim() == "quit" {
                        eprintln!("Quit command received, disconnecting...");
                        shutdown_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Thread: network -> stdout
    let log_out = logfile.clone();
    let shutdown_check = Arc::clone(&shutdown);
    let stdout_thread = thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            // Check if we should shutdown
            if shutdown_check.load(Ordering::SeqCst) {
                break;
            }
            
            match read_stream.read(&mut buf) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                    
                    // Log incoming data (from server) if logging is enabled
                    if let Some(ref log) = log_out {
                        if let Ok(mut log) = log.lock() {
                            let _ = log.write_all(b"<< ");
                            let _ = log.write_all(&buf[..n]);
                            let _ = log.flush();
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock 
                           || e.kind() == io::ErrorKind::TimedOut => {
                    // Timeout, check shutdown flag again
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    let _ = stdin_thread.join();
    let _ = stdout_thread.join();
    
    // Shutdown the connection
    let _ = shutdown_stream.shutdown(Shutdown::Both);
    
    eprintln!("Disconnected from server");
}

fn parse_config_arg(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}