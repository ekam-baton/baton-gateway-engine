#[path = "../src/shield.rs"]
mod shield;

use shield::{calculate_shannon_entropy, check_chunked_entropy, ShieldFirewall};
use std::net::IpAddr;
use std::thread;

#[test]
fn test_shannon_entropy_calculation() {
    let plain_text = b"GET /api/v1/vault HTTP/1.1\r\nHost: api.baton.ai\r\n\r\n";
    let low_entropy = calculate_shannon_entropy(plain_text);
    assert!(low_entropy < 5.0, "Plaintext HTTP should have low entropy, got {}", low_entropy);

    // High entropy artificial payload (pseudo-random shellcode bytes)
    let random_bytes: Vec<u8> = (0..256).map(|i| (i * 37 % 256) as u8).collect();
    let high_entropy = calculate_shannon_entropy(&random_bytes);
    assert!(high_entropy > 7.5, "Random binary shellcode should have high entropy (>7.5), got {}", high_entropy);
}

#[test]
fn test_ip_blacklisting_and_rehabilitation() {
    let shield = ShieldFirewall::new(3, 1); // 3 violations = 1s blacklist
    let attacker_ip: IpAddr = "192.168.1.100".parse().unwrap();

    assert!(!shield.is_blacklisted(&attacker_ip));

    // Log 2 violations
    shield.record_violation(attacker_ip, "Invalid signature test");
    shield.record_violation(attacker_ip, "Invalid signature test");
    assert!(!shield.is_blacklisted(&attacker_ip));

    // 3rd violation triggers blacklist
    shield.record_violation(attacker_ip, "Invalid signature test");
    assert!(shield.is_blacklisted(&attacker_ip), "IP should be blacklisted after 3 violations");

    // Wait 1.1 seconds for rehabilitation
    thread::sleep(std::time::Duration::from_millis(1100));
    assert!(!shield.is_blacklisted(&attacker_ip), "IP should be rehabilitated after blacklist duration expires");
}

#[test]
fn test_loopback_is_never_blacklisted() {
    let shield = ShieldFirewall::new(1, 3600);
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();

    shield.record_violation(loopback, "Test loopback protection");
    assert!(!shield.is_blacklisted(&loopback), "Loopback IP 127.0.0.1 must NEVER be blacklisted");
}

#[test]
fn test_proxy_real_ip_resolution() {
    let socket_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let headers = "GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.195, 127.0.0.1\r\n\r\n";

    let real_ip = ShieldFirewall::resolve_real_ip(socket_ip, headers, &[]);
    assert_eq!(real_ip, "203.0.113.195".parse::<IpAddr>().unwrap(), "Should extract true client IP from X-Forwarded-For");
}

#[test]
fn test_multithreaded_concurrent_stress() {
    let shield = std::sync::Arc::new(ShieldFirewall::new(30, 60));
    let mut handles = vec![];

    for i in 0..10 {
        let shield_clone = std::sync::Arc::clone(&shield);
        let handle = thread::spawn(move || {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            for _ in 0..50 {
                shield_clone.record_violation(ip, "Concurrent stress test");
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify system remains fully responsive and stable under concurrent load
    let test_ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(shield.is_blacklisted(&test_ip));
}
