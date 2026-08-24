use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_IP_TRACK_CAPACITY: usize = 50_000;

/// Calculates Shannon Entropy on a byte slice: H(X) = - sum(P(x) * log2(P(x)))
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut byte_counts = [0usize; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &count in byte_counts.iter() {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Checks sliding 64-byte chunks for localized high entropy spikes (shellcode detection)
pub fn check_chunked_entropy(data: &[u8], threshold: f64) -> bool {
    if data.len() < 64 {
        return calculate_shannon_entropy(data) > threshold;
    }
    for chunk in data.chunks(64) {
        if chunk.len() >= 32 && calculate_shannon_entropy(chunk) > threshold {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct IpReputation {
    pub violations: usize,
    pub last_violation: Instant,
    pub is_blacklisted: bool,
}

pub struct ShieldFirewall {
    // Lock-free concurrent hashmap for multi-gigabit throughput
    reputation_matrix: DashMap<IpAddr, IpReputation>,
    max_violations: usize,
    blacklist_duration: Duration,
}

impl ShieldFirewall {
    pub fn new(max_violations: usize, blacklist_secs: u64) -> Self {
        Self {
            reputation_matrix: DashMap::new(),
            max_violations,
            blacklist_duration: Duration::from_secs(blacklist_secs),
        }
    }

    pub fn resolve_real_ip(socket_ip: IpAddr, header_str: &str, trusted_proxies: &[IpAddr]) -> IpAddr {
        if !trusted_proxies.contains(&socket_ip) {
            return socket_ip; // Don't trust forwarded headers from untrusted sources
        }
        for line in header_str.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("x-real-ip:") || lower.starts_with("x-forwarded-for:") {
                if let Some(val) = line.splitn(2, ':').nth(1) {
                    let ips: Vec<&str> = val.split(',').collect();
                    // Iterate from right (most trusted) to left to find the first untrusted IP
                    for ip_str in ips.iter().rev() {
                        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                            if !trusted_proxies.contains(&ip) && !ip.is_loopback() {
                                return ip;
                            }
                        }
                    }
                }
            }
        }
        socket_ip
    }

    /// Checks if an IP is currently blacklisted.
    pub fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        if ip.is_loopback() {
            return false; // Loopback is never blacklisted
        }
        if let Some(mut ref_mut) = self.reputation_matrix.get_mut(ip) {
            let rep = ref_mut.value_mut();
            if rep.is_blacklisted {
                if rep.last_violation.elapsed() > self.blacklist_duration {
                    rep.is_blacklisted = false;
                    rep.violations = 0;
                    eprintln!("[BATON-SHIELD] IP {} blacklist expired. Rehabilitated.", ip);
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Records a security violation with OOM protection (capping map at MAX_IP_TRACK_CAPACITY).
    pub fn record_violation(&self, ip: IpAddr, reason: &str) {
        if ip.is_loopback() {
            eprintln!("[BATON-SHIELD] Warning on Loopback IP: {}", reason);
            return;
        }

        // Memory Guard: Prune map if flooded with unique botnet IPs
        if self.reputation_matrix.len() >= MAX_IP_TRACK_CAPACITY {
            self.reputation_matrix.retain(|_, v| v.is_blacklisted || v.last_violation.elapsed() < Duration::from_secs(300));
        }

        let mut entry = self.reputation_matrix.entry(ip).or_insert(IpReputation {
            violations: 0,
            last_violation: Instant::now(),
            is_blacklisted: false,
        });

        entry.violations += 1;
        entry.last_violation = Instant::now();

        eprintln!("[BATON-SHIELD] Security violation logged for IP {}: {} (Total: {})", ip, reason, entry.violations);

        if entry.violations >= self.max_violations {
            entry.is_blacklisted = true;
            eprintln!("[BATON-SHIELD] 🚨 IP {} BLACKLISTED for breach of threshold ({}/{} violations)", ip, entry.violations, self.max_violations);
        }
    }

    /// Inspects HTTP Header strings and URI paths for high entropy obfuscation / shellcode / SQLi
    pub fn inspect_headers_and_uri(&self, ip: IpAddr, header_str: &str) -> Result<(), String> {
        if self.is_blacklisted(&ip) {
            return Err(format!("IP {} is blacklisted by BATON-Shield Firewall", ip));
        }

        let lower_headers = header_str.to_lowercase();
        
        // Strict pattern matching for zero-day payloads, SQLi, path traversal
        let malicious_patterns = ["../", "..\\", "<script>", "union select", "waitfor delay", "eval(", "/etc/passwd", "cmd.exe"];
        for pattern in malicious_patterns.iter() {
            if lower_headers.contains(pattern) {
                // Immediate ban (add max violations)
                for _ in 0..self.max_violations {
                    self.record_violation(ip, &format!("Malicious pattern detected: {}", pattern));
                }
                self.log_to_file(ip, "Malicious pattern match");
                return Err(format!("BATON-Shield: Malicious pattern detected: {}", pattern));
            }
        }

        // Check header strings for localized high-entropy shellcode (threshold > 7.0 for stricter blocking)
        if check_chunked_entropy(header_str.as_bytes(), 7.0) {
            // Immediate ban for high entropy
            for _ in 0..self.max_violations {
                self.record_violation(ip, "High entropy detected in HTTP headers (Obfuscated attack vector)");
            }
            self.log_to_file(ip, "High entropy shellcode");
            return Err("BATON-Shield: High entropy detected in HTTP headers".to_string());
        }

        Ok(())
    }

    /// Appends the block event to a persistent JSONL audit log
    fn log_to_file(&self, ip: IpAddr, reason: &str) {
        use std::io::Write;
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let log_entry = format!(r#"{{"timestamp": {}, "ip": "{}", "reason": "{}"}}"#, timestamp, ip, reason);
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open("firewall_blocks.jsonl") {
            let _ = writeln!(file, "{}", log_entry);
        }
    }
}
