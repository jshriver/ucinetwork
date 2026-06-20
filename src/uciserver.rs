// server.rs
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Sha256, Digest};
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    engine: String,
    bind_address: String,
}

const KEY_FILE: &str = "server.key";

fn load_or_create_key() -> String {
    if let Ok(key) = fs::read_to_string(KEY_FILE) {
        let key = key.trim().to_string();
        if !key.is_empty() {
            println!("Loaded auth key from {}: {}", KEY_FILE, key);
            return key;
        }
    }

    let key = generate_uuid_v4();
    fs::write(KEY_FILE, &key).expect("failed to write server.key");
    println!("Generated new auth key (saved to {}): {}", KEY_FILE, key);
    key
}

fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];

    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
        f.read_exact(&mut bytes).expect("failed to read random bytes");
    }

    #[cfg(windows)]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        let pid = std::process::id();
        let seed = t ^ (pid << 16) ^ (pid >> 16);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((seed >> (i % 32)) ^ (seed.wrapping_mul(i as u32 + 1))) as u8;
        }
    }

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Derive a ChaCha20 key (32 bytes) and nonce (12 bytes) from the UUID string.
/// Both client and server derive the same values from the shared secret.
fn derive_key_nonce(auth_key: &str) -> ([u8; 32], [u8; 12]) {
    // First hash: 32-byte ChaCha20 key
    let mut hasher = Sha256::new();
    hasher.update(b"chacha20-key:");
    hasher.update(auth_key.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    // Second hash: first 12 bytes used as nonce
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
    let config_file = parse_config_arg(&args).unwrap_or_else(|| "server.json".to_string());

    let cfg_data = fs::read_to_string(&config_file)
        .expect(&format!("failed to read {}", config_file));
    let cfg: Config = serde_json::from_str(&cfg_data)
        .expect("failed to parse config");

    let auth_key = load_or_create_key();

    println!("Detecting external IP address...");
    match get_external_ip() {
        Ok(ip) => println!("External IP: {}", ip),
        Err(e) => eprintln!("Failed to get external IP: {}", e),
    }

    let listener = TcpListener::bind(&cfg.bind_address)
        .expect(&format!("failed to bind to {}", cfg.bind_address));

    println!("Server listening on {}", cfg.bind_address);
    println!("Waiting for connections...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                println!("Client connected: {}", peer);

                if authenticate(&stream, &auth_key) {
                    println!("Client authenticated: {}", peer);
                    handle_client(stream, &cfg, &auth_key);
                    println!("Client disconnected: {}", peer);
                } else {
                    println!("Client failed auth, disconnecting: {}", peer);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

/// Read the first (plaintext) line and verify it matches the auth key.
fn authenticate(stream: &TcpStream, auth_key: &str) -> bool {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => return false,
        Ok(_) => {}
    }

    stream.set_read_timeout(None).ok();

    line.trim() == auth_key
}

fn handle_client(stream: TcpStream, cfg: &Config, auth_key: &str) {
    let (key, nonce) = derive_key_nonce(auth_key);

    let mut cmd = Command::new(&cfg.engine);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().expect("failed to spawn engine");
    let mut engine_stdin = child.stdin.take().expect("engine stdin");
    let mut engine_stdout = child.stdout.take().expect("engine stdout");

    let read_stream = stream.try_clone().expect("failed to clone stream");
    let write_stream = stream;

    // Thread: network (encrypted) -> engine stdin (plaintext)
    let key_recv = key;
    let nonce_recv = nonce;
    let stdin_thread = thread::spawn(move || {
        let mut cipher = ChaCha20::new(&key_recv.into(), &nonce_recv.into());
        let mut buf = [0u8; 4096];
        let mut read_stream = read_stream;
        loop {
            let n = match read_stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            cipher.apply_keystream(&mut buf[..n]);
            if engine_stdin.write_all(&buf[..n]).is_err() {
                break;
            }
            let _ = engine_stdin.flush();
        }
    });

    // Thread: engine stdout (plaintext) -> network (encrypted)
    let key_send = key;
    let nonce_send = nonce;
    let stdout_thread = thread::spawn(move || {
        let mut cipher = ChaCha20::new(&key_send.into(), &nonce_send.into());
        let mut buf = [0u8; 4096];
        let mut write_stream = write_stream;
        loop {
            let n = match engine_stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            cipher.apply_keystream(&mut buf[..n]);
            if write_stream.write_all(&buf[..n]).is_err() {
                break;
            }
            let _ = write_stream.flush();
        }
    });

    let _ = stdin_thread.join();
    let _ = stdout_thread.join();
    let _ = child.kill();
    let _ = child.wait();
}

fn get_external_ip() -> Result<String, Box<dyn std::error::Error>> {
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
    if let Ok(output) = Command::new("curl")
        .args(["-s", "-4", "--max-time", "5", url])
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    if let Ok(output) = Command::new("wget")
        .args(["-qO-", "--timeout=5", url])
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .arg("-Command")
            .arg(format!(
                "(Invoke-WebRequest -Uri {} -UseBasicParsing -TimeoutSec 5).Content",
                url
            ))
            .output()
        {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
    }

    Err("Failed to fetch IP".into())
}

fn parse_config_arg(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}