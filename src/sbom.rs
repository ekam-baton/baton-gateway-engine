use std::sync::Arc;
use tokio::sync::Mutex;
use crate::TelemetryStore;
use reqwest::Client;
use std::fs;

pub async fn scan_dependencies(telemetry: Arc<Mutex<TelemetryStore>>) {
    telemetry.lock().await.push("INFO", "Starting Automated SBOM Scanner...".to_string());
    let client = Client::new();

    // Very naive parser for demonstration: read Cargo.toml, find dependencies
    let cargo_toml = match fs::read_to_string("Cargo.toml") {
        Ok(c) => c,
        Err(e) => {
            telemetry.lock().await.push("WARN", format!("SBOM Scanner could not read Cargo.toml: {}", e));
            return;
        }
    };

    let mut dependencies = Vec::new();
    let mut in_deps = false;

    for line in cargo_toml.lines() {
        let line = line.trim();
        if line.starts_with("[dependencies]") {
            in_deps = true;
            continue;
        } else if line.starts_with('[') {
            in_deps = false;
        }

        if in_deps && !line.is_empty() && !line.starts_with('#') {
            if let Some((name, _)) = line.split_once('=') {
                let pkg_name = name.trim().to_string();
                dependencies.push(serde_json::json!({
                    "package": {
                        "name": pkg_name,
                        "ecosystem": "crates.io"
                    }
                }));
            }
        }
    }

    if dependencies.is_empty() {
        telemetry.lock().await.push("INFO", "SBOM Scanner found no dependencies to scan.".to_string());
        return;
    }

    telemetry.lock().await.push("INFO", format!("Scanning {} dependencies against OSV.dev...", dependencies.len()));

    let osv_req = serde_json::json!({
        "queries": dependencies
    });

    match client.post("https://api.osv.dev/v1/querybatch")
        .json(&osv_req)
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(results) = json.get("results").and_then(|v| v.as_array()) {
                    let mut found_vulns = 0;
                    for (i, result) in results.iter().enumerate() {
                        if result.get("vulns").is_some() {
                            let pkg_name = dependencies[i]["package"]["name"].as_str().unwrap_or("unknown");
                            telemetry.lock().await.push("CRITICAL", format!("SBOM Scanner found vulnerabilities in crate '{}'", pkg_name));
                            found_vulns += 1;
                        }
                    }
                    if found_vulns == 0 {
                        telemetry.lock().await.push("INFO", "SBOM Scanner finished cleanly. No known CVEs found in Cargo.toml.".to_string());
                    }
                }
            }
        }
        Err(e) => {
            telemetry.lock().await.push("WARN", format!("SBOM Scanner failed to contact OSV.dev: {}", e));
        }
    }
}
