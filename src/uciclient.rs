// client.rs
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, Shutdown};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Sha256, Digest};
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    server_address: String,
    auth_key: String,
    logfile: String,
    enable_logging: bool,
}

/// Derive a ChaCha20 key (32 bytes) and nonce (12 bytes) from the UUID string.
fn derive_key_nonce(auth_key: &str) -> ([u8; 32], [u8; 12]) {
    let mut hasher = Sha256::new();
    hasher.update(b"chacha20-key:");
    hasher.update(auth_key.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(b"chacha20-nonce:");
    hasher.update(auth_key.as_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[..12]);

    (key, nonce)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config_file = parse_config_arg(&args).unwrap_or_else(|| "client.json".to_string());

    let cfg_data = fs::read_to_string(&config_file)
        .expect(&format!("failed to read {}", config_file));
    let cfg: Config = serde_json::from_str(&cfg_data)
        .expect("failed to parse config");

    let logfile = if cfg.enable_logging {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&cfg.logfile)
                .expect("failed to open logfile"),
        )))
    } else {
        None
    };

    eprintln!("Connecting to server at {}...", cfg.server_address);
    let stream = TcpStream::connect(&cfg.server_address)
        .expect(&format!("failed to connect to {}", cfg.server_address));

    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("failed to set read timeout");

    eprintln!("Connected. Authenticating...");

    // Send auth key as plaintext — this is intentional, it's the shared secret
    // and both sides use it to derive the cipher key afterwards.
    {
        let mut auth_stream = stream.try_clone().expect("failed to clone stream for auth");
        let key_line = format!("{}\n", cfg.auth_key.trim());
        auth_stream
            .write_all(key_line.as_bytes())
            .expect("failed to send auth key");
        auth_stream.flush().expect("failed to flush auth key");
    }

    eprintln!("Auth key sent. Starting encrypted UCI session...");
    if cfg.enable_logging {
        eprintln!("Logging enabled: {}", cfg.logfile);
    }

    let (key, nonce) = derive_key_nonce(&cfg.auth_key);
    let shutdown = Arc::new(AtomicBool::new(false));

    let read_stream = stream.try_clone().expect("failed to clone stream");
    let write_stream = stream.try_clone().expect("failed to clone stream");
    let shutdown_stream = stream.try_clone().expect("failed to clone stream");

    // Thread: stdin (plaintext) -> network (encrypted)
    let log_in = logfile.clone();
    let shutdown_flag = Arc::clone(&shutdown);
    let key_send = key;
    let nonce_send = nonce;
    let stdin_thread = thread::spawn(move || {
        let mut cipher = ChaCha20::new(&key_send.into(), &nonce_send.into());
        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        let mut write_stream = write_stream;

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let line_with_newline = format!("{}\n", line);
                    let mut bytes = line_with_newline.into_bytes();

                    // Log plaintext before encrypting
                    if let Some(ref log) = log_in {
                        if let Ok(mut log) = log.lock() {
                            let _ = log.write_all(b">> ");
                            let _ = log.write_all(&bytes);
                            let _ = log.flush();
                        }
                    }

                    // Encrypt in place then send
                    cipher.apply_keystream(&mut bytes);
                    if write_stream.write_all(&bytes).is_err() {
                        break;
                    }
                    let _ = write_stream.flush();

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

    // Thread: network (encrypted) -> stdout (plaintext)
    let log_out = logfile.clone();
    let shutdown_check = Arc::clone(&shutdown);
    let key_recv = key;
    let nonce_recv = nonce;
    let stdout_thread = thread::spawn(move || {
        let mut cipher = ChaCha20::new(&key_recv.into(), &nonce_recv.into());
        let mut stdout = io::stdout();
        let mut buf = [0u8; 4096];
        let mut read_stream = read_stream;

        loop {
            if shutdown_check.load(Ordering::SeqCst) {
                break;
            }

            match read_stream.read(&mut buf) {
                Ok(0) => {
                    eprintln!("Server closed connection (auth may have failed — check your auth_key).");
                    break;
                }
                Ok(n) => {
                    // Decrypt in place
                    cipher.apply_keystream(&mut buf[..n]);

                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();

                    // Log plaintext after decrypting
                    if let Some(ref log) = log_out {
                        if let Ok(mut log) = log.lock() {
                            let _ = log.write_all(b"<< ");
                            let _ = log.write_all(&buf[..n]);
                            let _ = log.flush();
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    let _ = stdin_thread.join();
    let _ = stdout_thread.join();
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