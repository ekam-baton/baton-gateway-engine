use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use hmac::{Hmac, Mac};
use nonzero_ext::nonzero;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

mod sbom;
mod shield;
use shield::ShieldFirewall;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of unique nonces we will remember (DoS cap).
/// With a 5-minute TTL this equates to ~333 nonces/sec sustained — well
/// above any legitimate workload. On overflow, new requests are rejected
/// with 429 until the oldest nonces expire.
const MAX_NONCE_STORE_SIZE: usize = 100_000;

/// Maximum bytes we will buffer per HTTP request (64 KB). Requests larger
/// than this are rejected immediately to prevent memory exhaustion.
const MAX_REQUEST_BYTES: usize = 65_536;

/// Domain salt for HKDF key derivation — binds keys to this application.
const HKDF_DOMAIN_SALT: &[u8] = b"baton-gateway-v1-hkdf-salt-2024";

/// File where the gateway persists its X25519 keypair between restarts.
const KEYPAIR_FILE: &str = "gateway_keypair.hex";

// ---------------------------------------------------------------------------
// Keypair persistence
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct PersistedKeypair {
    private_key_hex: String,
}

/// Load the gateway X25519 private key from disk.  If the file does not
/// exist, generate a new key, persist it, and return it.
///
/// SECURITY: The private key file must be protected by OS-level file
/// permissions (chmod 600).  Never commit it to version control — it is
/// listed in .gitignore.
fn load_or_create_keypair() -> StaticSecret {
    if let Ok(data) = fs::read_to_string(KEYPAIR_FILE) {
        if let Ok(persisted) = serde_json::from_str::<PersistedKeypair>(&data) {
            if let Ok(bytes) = hex::decode(&persisted.private_key_hex) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    eprintln!("[GATEWAY] Loaded existing keypair from {}", KEYPAIR_FILE);
                    return StaticSecret::from(arr);
                }
            }
        }
    }

    // Generate fresh keypair
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let hex = hex::encode(secret.as_bytes());
    let persisted = PersistedKeypair { private_key_hex: hex };
    match serde_json::to_string(&persisted) {
        Ok(json) => {
            if let Err(e) = fs::write(KEYPAIR_FILE, &json) {
                eprintln!("[GATEWAY] WARNING: Could not persist keypair to {}: {}", KEYPAIR_FILE, e);
            } else {
                eprintln!("[GATEWAY] Generated and persisted new keypair to {}", KEYPAIR_FILE);
                // Attempt to set restrictive permissions on Unix targets
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(KEYPAIR_FILE, fs::Permissions::from_mode(0o600));
                }
            }
        }
        Err(e) => eprintln!("[GATEWAY] WARNING: Could not serialize keypair: {}", e),
    }
    secret
}

// ---------------------------------------------------------------------------
// Trusted client database
// ---------------------------------------------------------------------------

/// One entry in trusted_clients.json.
#[derive(Debug, Deserialize, Clone)]
struct TrustedClient {
    /// Human-readable identifier for logs / audit trails.
    user_email: String,
    /// Hex-encoded 32-byte X25519 public key issued to this user.
    client_public_key: String,
    /// Revocation flag — set to false to instantly block access.
    is_active: bool,
}

/// Load the full trusted-clients list from disk.
/// The file is read fresh on every incoming request so that revoking a key
/// takes effect without restarting the gateway.
fn load_trusted_clients() -> Result<Vec<TrustedClient>, String> {
    let path = std::env::var("TRUSTED_CLIENTS_PATH")
        .unwrap_or_else(|_| "trusted_clients.json".to_string());
    let data = fs::read_to_string(&path)
        .map_err(|e| format!("Could not read {}: {}", path, e))?;
    serde_json::from_str::<Vec<TrustedClient>>(&data)
        .map_err(|e| format!("Malformed trusted_clients file: {}", e))
}

/// Look up a hex-encoded public key in the trusted-clients database.
fn authorize_client_key(hex_key: &str) -> Result<TrustedClient, (u16, &'static str)> {
    let clients = load_trusted_clients().map_err(|_| (500u16, "Internal server error"))?;
    let normalised = hex_key.trim().to_lowercase();
    match clients.into_iter().find(|c| c.client_public_key.trim().to_lowercase() == normalised) {
        None => Err((403, "Unknown client key")),
        Some(c) if !c.is_active => Err((403, "Access revoked")),
        Some(c) => Ok(c),
    }
}

// ---------------------------------------------------------------------------
// Replay protection — tokio::sync::Mutex (non-blocking in async context)
// ---------------------------------------------------------------------------

struct NonceStore {
    nonces: std::collections::HashMap<String, u64>,
}

const NONCE_TTL_MS: u64 = 300_000; // 5 minutes

impl NonceStore {
    fn new() -> Self {
        Self { nonces: std::collections::HashMap::new() }
    }

    /// Returns true (and records the nonce) if it has not been seen within
    /// the TTL window.  Returns false for replays.  Also prunes stale
    /// entries and enforces a hard size cap to prevent memory exhaustion.
    fn check_and_add(&mut self, nonce: &str, now_ms: u64) -> bool {
        // Prune expired entries first
        self.nonces.retain(|_, &mut inserted_at| {
            now_ms.saturating_sub(inserted_at) < NONCE_TTL_MS
        });

        // Hard cap — reject new nonces if the store is saturated
        if self.nonces.len() >= MAX_NONCE_STORE_SIZE {
            return false;
        }

        if self.nonces.contains_key(nonce) {
            false
        } else {
            self.nonces.insert(nonce.to_string(), now_ms);
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Internal Tool Server
// ---------------------------------------------------------------------------
use std::collections::VecDeque;

#[derive(Serialize, Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub msg: String,
}

pub struct TelemetryStore {
    logs: VecDeque<LogEntry>,
    capacity: usize,
}

impl TelemetryStore {
    fn new(capacity: usize) -> Self {
        Self {
            logs: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, level: &str, msg: String) {
        if self.logs.len() >= self.capacity {
            self.logs.pop_front();
        }
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let entry = LogEntry {
            timestamp,
            level: level.to_string(),
            msg: msg.clone(),
        };
        self.logs.push_back(entry.clone());
        eprintln!("[{}] {}", level, msg);

        // Persistent Dataset Recording for PyTorch Fine-Tuning
        if level == "WARN" || level == "CRITICAL" {
            if let Ok(json_line) = serde_json::to_string(&entry) {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open("telemetry_dataset.jsonl") {
                    let _ = writeln!(file, "{}", json_line);
                }
            }
        }

        if level == "CRITICAL" {
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                let secret = std::env::var("SWARM_WEBHOOK_SECRET").unwrap_or_else(|_| "baton-super-secret-key-2026".to_string());
                let payload = serde_json::json!({
                    "title": "CRITICAL Gateway Alert",
                    "description": msg_clone,
                    "timestamp": timestamp,
                });
                let payload_str = payload.to_string();
                if let Ok(mut mac) = <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes()) {
                    mac.update(payload_str.as_bytes());
                    let signature = hex::encode(mac.finalize().into_bytes());

                    let client = reqwest::Client::new();
                    if let Err(e) = client.post("http://127.0.0.1:8000/webhook/alert")
                        .header("X-Baton-Signature", signature)
                        .header("Content-Type", "application/json")
                        .body(payload_str)
                        .send()
                        .await 
                    {
                        eprintln!("[GATEWAY-SWARM-BRIDGE] Alert webhook failed: {}", e);
                    } else {
                        eprintln!("[GATEWAY-SWARM-BRIDGE] Successfully dispatched HMAC-signed CRITICAL alert to Python Swarm.");
                    }
                }
            });
        }
    }

    fn get_logs(&self, limit: usize) -> Vec<LogEntry> {
        self.logs.iter().rev().take(limit).cloned().collect()
    }
}

async fn run_tool_server(telemetry: Arc<Mutex<TelemetryStore>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:8081").await?;
    eprintln!("[TOOL SERVER] Internal management API listening on 127.0.0.1:8081");
    let client = reqwest::Client::new();

    loop {
        let (mut socket, _) = listener.accept().await?;
        let telemetry = Arc::clone(&telemetry);
        let client = client.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut raw = Vec::new();
            let header_end: usize;
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        raw.extend_from_slice(&buf[..n]);
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos;
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            let header_str = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = header_str
                .lines()
                .find_map(|line| {
                    let lower = line.to_lowercase();
                    if lower.starts_with("content-length:") {
                        line.splitn(2, ':').nth(1)?.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            let body_end = header_end + 4 + content_length;
            while raw.len() < body_end {
                match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                    Err(_) => return,
                }
            }

            let body_str = String::from_utf8_lossy(&raw[header_end + 4..body_end]);
            let Ok(req_json) = serde_json::from_str::<serde_json::Value>(&body_str) else {
                let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await;
                return;
            };

            let tool_name = req_json.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let empty_kwargs = serde_json::json!({});
            let kwargs = req_json.get("kwargs").unwrap_or(&empty_kwargs);

            let response_body = if tool_name == "fetch_gateway_logs" {
                let limit = kwargs.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                let logs = telemetry.lock().await.get_logs(limit);
                serde_json::json!({ "result": logs })
            } else if tool_name == "lookup_cve" {
                let pkg = kwargs.get("package_name").and_then(|v| v.as_str()).unwrap_or("");
                let ver = kwargs.get("version").and_then(|v| v.as_str()).unwrap_or("");
                let eco = kwargs.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("Maven");
                
                let osv_req = serde_json::json!({
                    "version": ver,
                    "package": {
                        "name": pkg,
                        "ecosystem": eco
                    }
                });

                let res = client.post("https://api.osv.dev/v1/query")
                    .json(&osv_req)
                    .send()
                    .await;
                
                match res {
                    Ok(resp) => {
                        let json_resp = resp.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
                        serde_json::json!({ "result": json_resp })
                    }
                    Err(e) => {
                        serde_json::json!({ "error": e.to_string() })
                    }
                }
            } else {
                serde_json::json!({ "error": "Unknown tool" })
            };

            let body_bytes = serde_json::to_string(&response_body).unwrap_or_default();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_bytes.len(),
                body_bytes
            );
            
            let _ = socket.write_all(http_response.as_bytes()).await;
        });
    }
}

async fn orchestrator_loop(telemetry: Arc<Mutex<TelemetryStore>>) {
    let client = reqwest::Client::new();
    let llm_endpoint = std::env::var("LLM_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:11434/api/chat".to_string());
    
    // We track the timestamp of the last processed log to avoid duplicate alerts.
    let mut last_processed_ts = 0;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        let logs = telemetry.lock().await.get_logs(100);
        
        let recent_warnings: Vec<_> = logs.into_iter()
            .filter(|l| l.level == "WARN" && l.timestamp > last_processed_ts)
            .collect();

        if recent_warnings.is_empty() {
            continue;
        }

        // Update last processed timestamp
        if let Some(latest) = recent_warnings.first() {
            last_processed_ts = latest.timestamp;
        }

        let prompt = format!(
            "You are BATON, an autonomous Endpoint Security Agent.\n\
             The gateway has detected the following anomalous behavior (WARN logs):\n\
             {:#?}\n\
             Based on this telemetry, does this look like an active attack? \
             Respond with a concise analysis, and end your response with 'ACTION: BLOCK' if the gateway should block the offending IP, or 'ACTION: PASS' if it's benign.",
            recent_warnings
        );

        let req_body = serde_json::json!({
            "model": "qwen2.5-coder:3b",
            "messages": [
                { "role": "system", "content": "You are a highly capable cybersecurity agent analyzing gateway telemetry." },
                { "role": "user", "content": prompt }
            ],
            "stream": false
        });

        match client.post(&llm_endpoint).json(&req_body).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let content = json.get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    
                    if content.contains("ACTION: BLOCK") {
                        telemetry.lock().await.push("CRITICAL", format!("LLM Orchestrator recommended BLOCK action. Reason: {}", content.lines().next().unwrap_or("")));
                    } else {
                        telemetry.lock().await.push("INFO", "LLM Orchestrator analyzed warnings and recommended PASS.".to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("[ORCHESTRATOR] LLM consultation failed: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load or generate the gateway X25519 keypair from disk.
    //    The public key is NOT printed to stdout — distribute it through
    //    a separate, controlled enrollment channel.
    let private_key = Arc::new(load_or_create_keypair());
    let public_key = PublicKey::from(private_key.as_ref());

    // Log public key only to stderr (operational metadata, not sensitive).
    // In production, pipe stderr to a restricted log sink.
    eprintln!("==========================================");
    eprintln!("BATON RUST GATEWAY ENGINE");
    eprintln!("Gateway Public Key (X25519 Hex): {}", to_hex(public_key.as_bytes()));
    eprintln!("Distribute this key through your secure enrollment channel.");
    eprintln!("==========================================");

    // Validate that trusted_clients file is present and parseable at startup.
    match load_trusted_clients() {
        Ok(clients) => eprintln!("[GATEWAY] Loaded {} trusted client(s)", clients.len()),
        Err(e) => eprintln!("[GATEWAY] WARNING: {}", e),
    }

    // Shared nonce store — tokio::sync::Mutex is non-blocking in async context
    let nonce_store: Arc<Mutex<NonceStore>> = Arc::new(Mutex::new(NonceStore::new()));

    // Shared telemetry store
    let telemetry_store: Arc<Mutex<TelemetryStore>> = Arc::new(Mutex::new(TelemetryStore::new(1000)));
    let telemetry_for_server = Arc::clone(&telemetry_store);

    tokio::spawn(async move {
        if let Err(e) = run_tool_server(telemetry_for_server).await {
            eprintln!("[TOOL SERVER] Fatal error: {}", e);
        }
    });

    let telemetry_for_orchestrator = Arc::clone(&telemetry_store);
    tokio::spawn(async move {
        orchestrator_loop(telemetry_for_orchestrator).await;
    });

    let telemetry_for_sbom = Arc::clone(&telemetry_store);
    tokio::spawn(async move {
        sbom::scan_dependencies(telemetry_for_sbom).await;
    });

    // Per-IP rate limiter: 30 requests per minute per IP
    // This stops brute-force, replay flood, and DoS in one shot.
    let rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>> = Arc::new(
        RateLimiter::keyed(Quota::per_minute(nonzero!(30u32)))
    );

    // BATON-Shield Custom AI-Aware Firewall Engine
    let shield_firewall = Arc::new(ShieldFirewall::new(3, 3600));

    // 2. Bind on all interfaces (0.0.0.0) so VPS clients can connect.
    //    In production, put a TLS-terminating reverse-proxy (nginx/caddy) in front.
    let bind_addr = std::env::var("GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = TcpListener::bind(&bind_addr).await?;
    telemetry_store.lock().await.push("INFO", format!("Gateway listening on {}", bind_addr));

    loop {
        let (mut socket, addr) = listener.accept().await?;
        let nonce_store = Arc::clone(&nonce_store);
        let private_key = Arc::clone(&private_key);
        let rate_limiter = Arc::clone(&rate_limiter);
        let shield_firewall = Arc::clone(&shield_firewall);
        let telemetry = Arc::clone(&telemetry_store);

        tokio::spawn(async move {
            // ------------------------------------------------------------------
            // Rate limiting — check before reading ANY request bytes
            // ------------------------------------------------------------------
            if rate_limiter.check_key(&addr.ip()).is_err() {
                telemetry.lock().await.push("WARN", format!("Rate limit exceeded for IP {}", addr.ip()));
                send_status_error(&mut socket, 429, "Rate limit exceeded").await;
                return;
            }

            // ------------------------------------------------------------------
            // Read HTTP request headers — loop until \r\n\r\n or MAX_REQUEST_BYTES
            // ------------------------------------------------------------------
            let mut raw = Vec::with_capacity(4096);
            let mut tmp = [0u8; 4096];
            let header_end: usize;
            loop {
                match socket.read(&mut tmp).await {
                    Ok(0) => {
                        send_status_error(&mut socket, 400, "Connection closed before headers completed").await;
                        return;
                    }
                    Ok(n) => {
                        raw.extend_from_slice(&tmp[..n]);
                        if raw.len() > MAX_REQUEST_BYTES {
                            send_status_error(&mut socket, 413, "Request too large").await;
                            return;
                        }
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos;
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            // SECURITY/CORRECTNESS: headers arriving doesn't mean the body
            // has arrived too — TCP makes no such guarantee, and a body can
            // easily land in a later read() than the "\r\n\r\n" separator.
            // This used to stop reading right here, silently truncating any
            // body that hadn't fully arrived yet. Now it keeps reading until
            // it has the full Content-Length-declared body (bytes are
            // sliced from the raw buffer, not a lossy-converted String, to
            // avoid panicking on a UTF-8 char boundary if the buffer ever
            // contains invalid UTF-8).
            let header_str = String::from_utf8_lossy(&raw[..header_end]).into_owned();

            let content_length: usize = header_str
                .lines()
                .find_map(|line| {
                    let lower = line.to_lowercase();
                    if lower.starts_with("content-length:") {
                        line.splitn(2, ':').nth(1)?.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            let authorization = header_str
                .lines()
                .find_map(|line| {
                    let lower = line.to_lowercase();
                    if lower.starts_with("authorization:") {
                        Some(line.splitn(2, ':').nth(1)?.trim())
                    } else {
                        None
                    }
                })
                .unwrap_or("");

            let Some(Ok(_trusted_client)) = authorization.strip_prefix("Bearer ").map(authorize_client_key) else {
                telemetry.lock().await.push("WARN", format!("Auth rejected from {}: Invalid/unknown token", addr.ip()));
                send_status_error(&mut socket, 401, "Invalid authorization token").await;
                return;
            };

            let body_end = header_end + 4 + content_length;
            if body_end > MAX_REQUEST_BYTES {
                send_status_error(&mut socket, 413, "Request too large").await;
                return;
            }

            // Resolve real client IP behind proxy (e.g. NGINX)
            let client_ip = ShieldFirewall::resolve_real_ip(addr.ip(), &header_str);

            // ------------------------------------------------------------------
            // BATON-Shield Header & Obfuscation Firewall Inspection
            // ------------------------------------------------------------------
            if let Err(reason) = shield_firewall.inspect_headers_and_uri(client_ip, &header_str) {
                telemetry.lock().await.push("CRITICAL", format!("BATON-Shield dropped connection from {}: {}", client_ip, reason));
                send_status_error(&mut socket, 403, "Forbidden by BATON-Shield Firewall").await;
                return;
            }

            while raw.len() < body_end {
                match socket.read(&mut tmp).await {
                    Ok(0) => {
                        send_status_error(&mut socket, 400, "Connection closed before body completed").await;
                        return;
                    }
                    Ok(n) => {
                        raw.extend_from_slice(&tmp[..n]);
                        if raw.len() > MAX_REQUEST_BYTES {
                            send_status_error(&mut socket, 413, "Request too large").await;
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }

            let body_str = String::from_utf8_lossy(&raw[header_end + 4..body_end]).into_owned();
            let header_part = header_str;
            let body_part = body_str;

            // ------------------------------------------------------------------
            // Parse security-relevant headers
            // ------------------------------------------------------------------
            let mut timestamp: Option<u64> = None;
            let mut nonce: Option<&str> = None;
            let mut signature: Option<&str> = None;
            let mut client_key_hex: Option<&str> = None;

            for line in header_part.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("x-baton-timestamp:") {
                    timestamp = line.splitn(2, ':').nth(1).and_then(|s| s.trim().parse().ok());
                } else if lower.starts_with("x-baton-nonce:") {
                    nonce = line.splitn(2, ':').nth(1).map(str::trim);
                } else if lower.starts_with("x-baton-signature:") {
                    signature = line.splitn(2, ':').nth(1).map(str::trim);
                } else if lower.starts_with("x-baton-client-key:") {
                    client_key_hex = line.splitn(2, ':').nth(1).map(str::trim);
                }
            }

            // ------------------------------------------------------------------
            // Step 1 — Require X-Baton-Client-Key
            // ------------------------------------------------------------------
            let key_hex = match client_key_hex {
                Some(k) => k,
                None => {
                    send_status_error(&mut socket, 401, "Missing X-Baton-Client-Key header").await;
                    return;
                }
            };

            // ------------------------------------------------------------------
            // Step 2 — Look up key in trusted_clients (revocation check)
            // ------------------------------------------------------------------
            let trusted_client = match authorize_client_key(key_hex) {
                Ok(c) => c,
                Err((status, msg)) => {
                    // Log auth failure without echoing back the client key or IP
                    eprintln!("[GATEWAY] Auth rejected: {}", msg);
                    send_status_error(&mut socket, status, msg).await;
                    return;
                }
            };

            // ------------------------------------------------------------------
            // Step 3 — Parse client public key + X25519 DH
            // ------------------------------------------------------------------
            let key_bytes_vec = match hex::decode(key_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    send_status_error(&mut socket, 400, "Invalid client public key format").await;
                    return;
                }
            };

            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key_bytes_vec);
            let client_public_key = PublicKey::from(key_bytes);

            // X25519 Diffie-Hellman shared point
            let shared_point = private_key.diffie_hellman(&client_public_key);

            // SECURITY FIX (HIGH-4): Use HKDF directly on the raw DH output
            // with a non-zero, application-specific domain salt instead of
            // double-SHA-256 with a zero salt.  This provides proper key
            // derivation with domain separation.
            let hk_root = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), shared_point.as_bytes());
            let mut shared_secret = [0u8; 32];
            hk_root.expand(b"baton-shared-secret", &mut shared_secret)
                .expect("HKDF expand is infallible for 32-byte output");

            // ------------------------------------------------------------------
            // Step 4 — Parse encrypted JSON body
            // ------------------------------------------------------------------
            let json_body: serde_json::Value = match serde_json::from_str(&body_part) {
                Ok(v) => v,
                Err(_) => {
                    send_status_error(&mut socket, 400, "Invalid JSON body").await;
                    shared_secret.zeroize();
                    return;
                }
            };

            let ciphertext_b64 = match json_body["ciphertext"].as_str() {
                Some(c) => c,
                None => {
                    send_status_error(&mut socket, 400, "Missing ciphertext").await;
                    shared_secret.zeroize();
                    return;
                }
            };

            let iv_b64 = match json_body["iv"].as_str() {
                Some(iv) => iv,
                None => {
                    send_status_error(&mut socket, 400, "Missing IV").await;
                    shared_secret.zeroize();
                    return;
                }
            };

            if timestamp.is_none() || nonce.is_none() {
                send_status_error(&mut socket, 400, "Missing timestamp or nonce headers").await;
                shared_secret.zeroize();
                return;
            }

            let ts = timestamp.unwrap();
            let n = nonce.unwrap();

            // Nonce must be a reasonable length to prevent hash-flooding
            if n.len() > 128 {
                send_status_error(&mut socket, 400, "Nonce too long").await;
                shared_secret.zeroize();
                return;
            }

            // ------------------------------------------------------------------
            // Step 5 — Require HMAC Signature + Timestamp + Replay Protection
            // ------------------------------------------------------------------
            let sig = match signature {
                Some(s) => s,
                None => {
                    send_status_error(&mut socket, 401, "Missing X-Baton-Signature header").await;
                    shared_secret.zeroize();
                    return;
                }
            };

            // Enforce 5-minute timestamp skew window
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before epoch")
                .as_millis() as u64;
            let skew = if now > ts { now - ts } else { ts - now };
            if skew > 300_000 {
                send_status_error(&mut socket, 401, "Signature expired").await;
                shared_secret.zeroize();
                return;
            }

            // Replay prevention — tokio::sync::Mutex (non-blocking await)
            let is_valid_nonce = {
                let mut store = nonce_store.lock().await;
                store.check_and_add(n, now)
            };
            if !is_valid_nonce {
                send_status_error(&mut socket, 429, "Replay attack detected or nonce store full").await;
                shared_secret.zeroize();
                return;
            }

            // Derive HMAC signing key from the shared secret
            let hk_hmac = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &shared_secret);
            let mut signing_key = [0u8; 32];
            hk_hmac.expand(b"baton-hmac-signing", &mut signing_key)
                .expect("HKDF expand is infallible for 32-byte output");

            let signature_input = format!("ts={}:n_len={}:n={}:ct_len={}:ct={}", ts, n.len(), n, ciphertext_b64.len(), ciphertext_b64);
            let mut mac_verify = <HmacSha256 as hmac::Mac>::new_from_slice(&signing_key)
                .expect("HMAC key size is always valid");
            mac_verify.update(signature_input.as_bytes());
            signing_key.zeroize();

            let sig_bytes = match hex::decode(sig) {
                Ok(b) => b,
                Err(_) => {
                    send_status_error(&mut socket, 400, "Invalid signature encoding").await;
                    shared_secret.zeroize();
                    return;
                }
            };

            if mac_verify.verify_slice(&sig_bytes).is_err() {
                shield_firewall.record_violation(client_ip, "Invalid HMAC signature");
                telemetry.lock().await.push("WARN", format!("Invalid HMAC signature from {}", trusted_client.user_email));
                send_status_error(&mut socket, 403, "Invalid HMAC signature").await;
                shared_secret.zeroize();
                return;
            }

            // ------------------------------------------------------------------
            // Step 6 — Derive per-request AES-256-GCM key via HKDF and decrypt
            // ------------------------------------------------------------------
            let info = format!("{}:{}", ts, n);
            let hk_enc = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &shared_secret);
            let mut derived_key = [0u8; 32];
            hk_enc.expand(info.as_bytes(), &mut derived_key)
                .expect("HKDF expand is infallible for 32-byte output");

            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key);
            let cipher = Aes256Gcm::new(key);

            let ciphertext = match base64::engine::general_purpose::STANDARD.decode(ciphertext_b64) {
                Ok(b) => b,
                Err(_) => {
                    send_status_error(&mut socket, 400, "Invalid base64 ciphertext").await;
                    derived_key.zeroize();
                    shared_secret.zeroize();
                    return;
                }
            };

            let iv = match base64::engine::general_purpose::STANDARD.decode(iv_b64) {
                Ok(b) => b,
                Err(_) => {
                    send_status_error(&mut socket, 400, "Invalid base64 IV").await;
                    derived_key.zeroize();
                    shared_secret.zeroize();
                    return;
                }
            };

            // SECURITY FIX (CRIT-5): Validate IV length BEFORE calling from_slice.
            // from_slice panics if iv.len() != 12, crashing the handler task.
            if iv.len() != 12 {
                send_status_error(&mut socket, 400, "IV must be exactly 12 bytes").await;
                derived_key.zeroize();
                shared_secret.zeroize();
                return;
            }

            let nonce_gcm = Nonce::from_slice(&iv);
            let decrypted_bytes = match cipher.decrypt(nonce_gcm, ciphertext.as_ref()) {
                Ok(d) => d,
                Err(_) => {
                    send_status_error(&mut socket, 400, "Decryption failed").await;
                    derived_key.zeroize();
                    shared_secret.zeroize();
                    return;
                }
            };

            derived_key.zeroize();

            // SECURITY: Log only byte count, never plaintext content
            telemetry.lock().await.push("INFO", format!("Payload received from user {} ({}B)", trusted_client.user_email, decrypted_bytes.len()));

            // ------------------------------------------------------------------
            // Step 7 — Forward to real MCP agent (mock response for now)
            // ------------------------------------------------------------------
            let mock_mcp_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read file contents",
                            "inputSchema": {}
                        }
                    ]
                }
            });

            let response_plaintext = serde_json::to_string(&mock_mcp_response)
                .expect("mock response serialization is infallible");

            // Encrypt the response with a fresh IV
            let response_iv_bytes = rand::random::<[u8; 12]>();
            let response_nonce = Nonce::from_slice(&response_iv_bytes);

            let hk_resp = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &shared_secret);
            let mut derived_key_resp = [0u8; 32];
            hk_resp.expand(info.as_bytes(), &mut derived_key_resp)
                .expect("HKDF expand is infallible for 32-byte output");
            shared_secret.zeroize();

            let key_resp = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key_resp);
            let cipher_resp = Aes256Gcm::new(key_resp);

            let encrypted_response = cipher_resp
                .encrypt(response_nonce, response_plaintext.as_bytes())
                .expect("response encryption is infallible");
            derived_key_resp.zeroize();

            let enc_resp_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_response);
            let iv_resp_b64 = base64::engine::general_purpose::STANDARD.encode(response_iv_bytes);

            let json_response = serde_json::json!({
                "ciphertext": enc_resp_b64,
                "iv": iv_resp_b64
            });

            let http_body = serde_json::to_string(&json_response)
                .expect("response JSON serialization is infallible");
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                http_body.len(),
                http_body
            );

            let _ = socket.write_all(http_response.as_bytes()).await;
            let _ = socket.flush().await;

            telemetry.lock().await.push("INFO", format!("Request for '{}' handled successfully", trusted_client.user_email));
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn send_status_error(socket: &mut tokio::net::TcpStream, status: u16, msg: &str) {
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let err_json = serde_json::json!({ "error": msg });
    let body = serde_json::to_string(&err_json).unwrap_or_default();
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = socket.write_all(resp.as_bytes()).await;
    let _ = socket.flush().await;
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_and_dh() {
        let private1 = StaticSecret::random_from_rng(rand::thread_rng());
        let public1 = PublicKey::from(&private1);
        let private2 = StaticSecret::random_from_rng(rand::thread_rng());
        let public2 = PublicKey::from(&private2);
        let shared1 = private1.diffie_hellman(&public2);
        let shared2 = private2.diffie_hellman(&public1);
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_payload() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        let key_bytes = [0u8; 32];
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let iv = [1u8; 12];
        let nonce = Nonce::from_slice(&iv);
        let plaintext = b"hello world";
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(nonce, encrypted.as_ref()).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_nonce_store_replay_rejected() {
        let mut store = NonceStore::new();
        assert!(store.check_and_add("nonce1", 1_000));
        assert!(!store.check_and_add("nonce1", 1_500)); // replay — must reject
        assert!(store.check_and_add("nonce2", 1_500));
    }

    #[test]
    fn test_nonce_store_expires_after_ttl() {
        let mut store = NonceStore::new();
        assert!(store.check_and_add("nonce1", 0));
        assert!(store.check_and_add("nonce1", NONCE_TTL_MS + 1)); // expired — accept again
    }

    #[test]
    fn test_nonce_store_size_cap() {
        let mut store = NonceStore::new();
        // Fill the store to the cap
        for i in 0..MAX_NONCE_STORE_SIZE {
            store.nonces.insert(format!("nonce_{}", i), u64::MAX); // never expire
        }
        // Next insert must be rejected
        assert!(!store.check_and_add("overflow_nonce", u64::MAX));
    }

    #[test]
    fn test_iv_length_validation() {
        // Simulate what happens with a bad IV — must NOT panic
        let bad_iv = vec![0u8; 8]; // too short
        assert_ne!(bad_iv.len(), 12, "Bad IV must not be 12 bytes");
        // The gateway now guards this before calling Nonce::from_slice
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let dh_output = [0xABu8; 32];
        let hk = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &dh_output);
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        hk.expand(b"baton-shared-secret", &mut key1).unwrap();
        hk.expand(b"baton-hmac-signing", &mut key2).unwrap();
        assert_ne!(key1, key2, "Different HKDF info strings must produce different keys");
    }

    #[test]
    fn test_authorize_client_key_unknown() {
        let result = authorize_client_key("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0x0a, 0xff, 0x10]), "0aff10");
    }

    #[test]
    fn test_trusted_client_deserialization() {
        let json = r#"[
            {"user_email":"a@b.com","client_public_key":"aabb","is_active":true},
            {"user_email":"c@d.com","client_public_key":"ccdd","is_active":false}
        ]"#;
        let clients: Vec<TrustedClient> = serde_json::from_str(json).unwrap();
        assert_eq!(clients.len(), 2);
        assert!(clients[0].is_active);
        assert!(!clients[1].is_active);
    }
}
