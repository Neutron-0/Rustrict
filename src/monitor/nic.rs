use colored::*;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicAdapterInfo {
    pub name: String,
    pub interface_index: u32,
    pub description: String,
    pub status: String,
    pub link_speed_str: String,
    pub link_speed_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NicRawStats {
    pub name: String,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub received_discarded: u64,
    pub received_errors: u64,
    pub outbound_discarded: u64,
    pub outbound_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NicHealthClassification {
    Normal,
    Elevated,
    Saturated,
    Degraded,
    Unavailable,
}

impl NicHealthClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Elevated => "Elevated",
            Self::Saturated => "Saturated",
            Self::Degraded => "Degraded",
            Self::Unavailable => "Unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicHealthReport {
    pub adapter: NicAdapterInfo,
    pub sample_duration: Duration,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
    pub rx_bytes_delta: u64,
    pub tx_bytes_delta: u64,
    pub rx_errors_delta: u64,
    pub tx_errors_delta: u64,
    pub rx_discards_delta: u64,
    pub tx_discards_delta: u64,
    pub rx_utilization_pct: f64,
    pub tx_utilization_pct: f64,
    pub classification: NicHealthClassification,
    pub classification_reason: String,
}

/// Abstract telemetry provider to allow testing without invoking live PowerShell.
pub trait NicTelemetryProvider: Send + Sync {
    fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String>;
    fn query_statistics(&self) -> Result<Vec<NicRawStats>, String>;
}

pub struct WindowsPowershellNicProvider;

impl NicTelemetryProvider for WindowsPowershellNicProvider {
    fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object -Property Name, InterfaceIndex, InterfaceDescription, Status, LinkSpeed | ConvertTo-Csv -NoTypeInformation",
            ])
            .output()
            .map_err(|e| format!("Failed to execute Get-NetAdapter: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Get-NetAdapter failed: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_adapters_csv(&stdout)
    }

    fn query_statistics(&self) -> Result<Vec<NicRawStats>, String> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetAdapterStatistics | Select-Object -Property Name, ReceivedBytes, SentBytes, ReceivedDiscardedPackets, ReceivedPacketErrors, OutboundDiscardedPackets, OutboundPacketErrors | ConvertTo-Csv -NoTypeInformation",
            ])
            .output()
            .map_err(|e| format!("Failed to execute Get-NetAdapterStatistics: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Get-NetAdapterStatistics failed: {}",
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_statistics_csv(&stdout)
    }
}

pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

pub fn parse_adapters_csv(csv_text: &str) -> Result<Vec<NicAdapterInfo>, String> {
    let mut lines = csv_text.lines().map(|l| l.trim()).filter(|l| !l.is_empty());
    let _header = match lines.next() {
        Some(h) => h,
        None => return Ok(Vec::new()),
    };

    let mut adapters = Vec::new();
    for line in lines {
        let fields = parse_csv_line(line);
        if fields.len() < 5 {
            continue;
        }
        let name = fields[0].clone();
        let interface_index: u32 = fields[1].parse().unwrap_or(0);
        let description = fields[2].clone();
        let status = fields[3].clone();
        let link_speed_str = fields[4].clone();
        let link_speed_bps = parse_link_speed_to_bps(&link_speed_str);

        adapters.push(NicAdapterInfo {
            name,
            interface_index,
            description,
            status,
            link_speed_str,
            link_speed_bps,
        });
    }

    Ok(adapters)
}

pub fn parse_statistics_csv(csv_text: &str) -> Result<Vec<NicRawStats>, String> {
    let mut lines = csv_text.lines().map(|l| l.trim()).filter(|l| !l.is_empty());
    let _header = match lines.next() {
        Some(h) => h,
        None => return Ok(Vec::new()),
    };

    let mut stats = Vec::new();
    for line in lines {
        let fields = parse_csv_line(line);
        if fields.len() < 7 {
            continue;
        }
        let name = fields[0].clone();
        let received_bytes: u64 = fields[1].parse().unwrap_or(0);
        let sent_bytes: u64 = fields[2].parse().unwrap_or(0);
        let received_discarded: u64 = fields[3].parse().unwrap_or(0);
        let received_errors: u64 = fields[4].parse().unwrap_or(0);
        let outbound_discarded: u64 = fields[5].parse().unwrap_or(0);
        let outbound_errors: u64 = fields[6].parse().unwrap_or(0);

        stats.push(NicRawStats {
            name,
            received_bytes,
            sent_bytes,
            received_discarded,
            received_errors,
            outbound_discarded,
            outbound_errors,
        });
    }

    Ok(stats)
}

pub fn parse_link_speed_to_bps(speed_str: &str) -> u64 {
    let clean = speed_str.trim();
    if clean.is_empty() || clean == "0" || clean == "0 bps" {
        return 0;
    }
    let parts: Vec<&str> = clean.split_whitespace().collect();
    if parts.is_empty() {
        return 0;
    }
    let num_val: f64 = match parts[0].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let unit = parts
        .get(1)
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let multiplier = match unit.as_str() {
        "gbps" | "gbit/s" | "g" => 1_000_000_000.0,
        "mbps" | "mbit/s" | "m" => 1_000_000.0,
        "kbps" | "kbit/s" | "k" => 1_000.0,
        "bps" | "bit/s" => 1.0,
        _ => 1.0,
    };
    (num_val * multiplier) as u64
}

pub fn evaluate_health_classification(
    adapter: &NicAdapterInfo,
    rx_util_pct: f64,
    tx_util_pct: f64,
    rx_err: u64,
    tx_err: u64,
    rx_disc: u64,
    tx_disc: u64,
) -> (NicHealthClassification, String) {
    if !adapter.status.eq_ignore_ascii_case("Up") || adapter.link_speed_bps == 0 {
        return (
            NicHealthClassification::Unavailable,
            format!(
                "Adapter status is '{}' (link speed: {} bps)",
                adapter.status, adapter.link_speed_bps
            ),
        );
    }

    if rx_err > 0 || tx_err > 0 || rx_disc > 0 || tx_disc > 0 {
        return (
            NicHealthClassification::Degraded,
            format!(
                "Active errors/discards observed during sampling interval (Rx err: {}, Tx err: {}, Rx disc: {}, Tx disc: {})",
                rx_err, tx_err, rx_disc, tx_disc
            ),
        );
    }

    let peak_util = rx_util_pct.max(tx_util_pct);
    if peak_util >= 90.0 {
        (
            NicHealthClassification::Saturated,
            format!(
                "Link utilization saturated at {:.1}% (threshold >= 90.0%)",
                peak_util
            ),
        )
    } else if peak_util >= 70.0 {
        (
            NicHealthClassification::Elevated,
            format!(
                "Link utilization elevated at {:.1}% (threshold >= 70.0%)",
                peak_util
            ),
        )
    } else {
        (
            NicHealthClassification::Normal,
            format!(
                "Link operating nominally at {:.1}% peak utilization",
                peak_util
            ),
        )
    }
}

pub fn format_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.2} Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.2} Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.2} Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{} bps", bps)
    }
}

pub fn sample_nic_health<P: NicTelemetryProvider>(
    provider: &P,
    adapter_filter: Option<&str>,
    sample_interval: Duration,
) -> Result<NicHealthReport, String> {
    let adapters = provider.query_adapters()?;
    if adapters.is_empty() {
        return Err("No network adapters detected on the system".into());
    }

    let target_adapter = if let Some(filter) = adapter_filter {
        adapters.iter().find(|a| {
            a.name.eq_ignore_ascii_case(filter)
                || a.interface_index.to_string() == filter
                || a.description
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
        })
    } else {
        adapters
            .iter()
            .find(|a| a.status.eq_ignore_ascii_case("Up"))
    };

    let adapter = match target_adapter {
        Some(a) => a.clone(),
        None => {
            return Err(match adapter_filter {
                Some(f) => format!("No network adapter matched filter '{}'", f),
                None => "No active ('Up') network adapter detected".to_string(),
            });
        }
    };

    // First sample (t0)
    let stats0_list = provider.query_statistics()?;
    let stats0 = stats0_list
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(&adapter.name))
        .unwrap_or_else(|| NicRawStats {
            name: adapter.name.clone(),
            ..Default::default()
        });

    sleep(sample_interval);

    // Second sample (t1)
    let stats1_list = provider.query_statistics()?;
    let stats1 = stats1_list
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(&adapter.name))
        .unwrap_or_else(|| NicRawStats {
            name: adapter.name.clone(),
            ..Default::default()
        });

    // Safe calculation: if counter was reset or wrapped, delta saturates to 0
    let rx_bytes_delta = stats1.received_bytes.saturating_sub(stats0.received_bytes);
    let tx_bytes_delta = stats1.sent_bytes.saturating_sub(stats0.sent_bytes);

    let rx_errors_delta = stats1
        .received_errors
        .saturating_sub(stats0.received_errors);
    let tx_errors_delta = stats1
        .outbound_errors
        .saturating_sub(stats0.outbound_errors);
    let rx_discards_delta = stats1
        .received_discarded
        .saturating_sub(stats0.received_discarded);
    let tx_discards_delta = stats1
        .outbound_discarded
        .saturating_sub(stats0.outbound_discarded);

    let elapsed_secs = sample_interval.as_secs_f64().max(0.001);
    let rx_rate_bps = ((rx_bytes_delta as f64 * 8.0) / elapsed_secs) as u64;
    let tx_rate_bps = ((tx_bytes_delta as f64 * 8.0) / elapsed_secs) as u64;

    let (rx_utilization_pct, tx_utilization_pct) = if adapter.link_speed_bps > 0 {
        (
            (rx_rate_bps as f64 / adapter.link_speed_bps as f64) * 100.0,
            (tx_rate_bps as f64 / adapter.link_speed_bps as f64) * 100.0,
        )
    } else {
        (0.0, 0.0)
    };

    let (classification, classification_reason) = evaluate_health_classification(
        &adapter,
        rx_utilization_pct,
        tx_utilization_pct,
        rx_errors_delta,
        tx_errors_delta,
        rx_discards_delta,
        tx_discards_delta,
    );

    Ok(NicHealthReport {
        adapter,
        sample_duration: sample_interval,
        rx_rate_bps,
        tx_rate_bps,
        rx_bytes_delta,
        tx_bytes_delta,
        rx_errors_delta,
        tx_errors_delta,
        rx_discards_delta,
        tx_discards_delta,
        rx_utilization_pct,
        tx_utilization_pct,
        classification,
        classification_reason,
    })
}

pub fn print_nic_report(report: &NicHealthReport) {
    println!(
        "\n{}",
        "=== Physical Network Adapter Health Diagnostic ==="
            .bold()
            .cyan()
    );
    println!(
        "Adapter:      {} (Index: {})",
        report.adapter.name.bold(),
        report.adapter.interface_index
    );
    println!("Description:  {}", report.adapter.description);
    println!(
        "Status:       {} | Declared Link Speed: {}",
        report.adapter.status, report.adapter.link_speed_str
    );
    println!(
        "Sample Time:  {:.1}s window",
        report.sample_duration.as_secs_f64()
    );

    println!("\n{}", "[Measured Telemetry]".bold());
    println!(
        "  Rx Rate:    {:>12} ({:>10} bytes)  |  Rx Utilization: {:>5.1}%",
        format_bps(report.rx_rate_bps),
        report.rx_bytes_delta,
        report.rx_utilization_pct
    );
    println!(
        "  Tx Rate:    {:>12} ({:>10} bytes)  |  Tx Utilization: {:>5.1}%",
        format_bps(report.tx_rate_bps),
        report.tx_bytes_delta,
        report.tx_utilization_pct
    );
    println!(
        "  Rx Discard: {:>12}  |  Rx Packet Errors: {:>6}",
        report.rx_discards_delta, report.rx_errors_delta
    );
    println!(
        "  Tx Discard: {:>12}  |  Tx Packet Errors: {:>6}",
        report.tx_discards_delta, report.tx_errors_delta
    );

    let (status_label, reason_colored) = match report.classification {
        NicHealthClassification::Normal => (
            "[HEALTH: NORMAL]".bright_green().bold(),
            report.classification_reason.green(),
        ),
        NicHealthClassification::Elevated => (
            "[HEALTH: ELEVATED]".yellow().bold(),
            report.classification_reason.yellow(),
        ),
        NicHealthClassification::Saturated => (
            "[HEALTH: SATURATED]".bright_magenta().bold(),
            report.classification_reason.bright_magenta(),
        ),
        NicHealthClassification::Degraded => (
            "[HEALTH: DEGRADED]".bright_red().bold(),
            report.classification_reason.bright_red(),
        ),
        NicHealthClassification::Unavailable => (
            "[HEALTH: UNAVAILABLE]".dimmed().bold(),
            report.classification_reason.dimmed(),
        ),
    };

    println!("\n{}", "[Heuristic Health Classification]".bold());
    println!("  Classification: {}", status_label);
    println!("  Diagnosis:      {}\n", reason_colored);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockNicProvider {
        adapters: Vec<NicAdapterInfo>,
        stats_samples: Arc<parking_lot::Mutex<Vec<Vec<NicRawStats>>>>,
        stats_calls: Arc<AtomicUsize>,
    }

    impl MockNicProvider {
        fn new(adapters: Vec<NicAdapterInfo>, samples: Vec<Vec<NicRawStats>>) -> Self {
            Self {
                adapters,
                stats_samples: Arc::new(parking_lot::Mutex::new(samples)),
                stats_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl NicTelemetryProvider for MockNicProvider {
        fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String> {
            Ok(self.adapters.clone())
        }

        fn query_statistics(&self) -> Result<Vec<NicRawStats>, String> {
            let idx = self.stats_calls.fetch_add(1, Ordering::SeqCst);
            let samples = self.stats_samples.lock();
            if idx < samples.len() {
                Ok(samples[idx].clone())
            } else if let Some(last) = samples.last() {
                Ok(last.clone())
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[test]
    fn test_parse_link_speed_units() {
        assert_eq!(parse_link_speed_to_bps("1.2 Gbps"), 1_200_000_000);
        assert_eq!(parse_link_speed_to_bps("1 Gbps"), 1_000_000_000);
        assert_eq!(parse_link_speed_to_bps("286.8 Mbps"), 286_800_000);
        assert_eq!(parse_link_speed_to_bps("100 Mbps"), 100_000_000);
        assert_eq!(parse_link_speed_to_bps("10 Kbps"), 10_000);
        assert_eq!(parse_link_speed_to_bps("500 bps"), 500);
        assert_eq!(parse_link_speed_to_bps("0 bps"), 0);
        assert_eq!(parse_link_speed_to_bps(""), 0);
    }

    #[test]
    fn test_csv_parser_with_quotes_and_commas() {
        let line = r#""Wi-Fi","16","MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter","Up","1.2 Gbps""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "Wi-Fi");
        assert_eq!(fields[1], "16");
        assert_eq!(
            fields[2],
            "MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter"
        );
        assert_eq!(fields[3], "Up");
        assert_eq!(fields[4], "1.2 Gbps");
    }

    #[test]
    fn test_nic_sample_health_normal() {
        let adapter = NicAdapterInfo {
            name: "Wi-Fi".into(),
            interface_index: 16,
            description: "Test Wi-Fi Adapter".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        // 100 KB in 50ms = 2 MB/s = 16 Mbps. 16 Mbps / 1 Gbps = 1.6%
        let sample0 = vec![NicRawStats {
            name: "Wi-Fi".into(),
            received_bytes: 10_000_000,
            sent_bytes: 2_000_000,
            received_discarded: 0,
            received_errors: 0,
            outbound_discarded: 0,
            outbound_errors: 0,
        }];
        let sample1 = vec![NicRawStats {
            name: "Wi-Fi".into(),
            received_bytes: 10_100_000,
            sent_bytes: 2_050_000,
            received_discarded: 0,
            received_errors: 0,
            outbound_discarded: 0,
            outbound_errors: 0,
        }];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Wi-Fi"), Duration::from_millis(50))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Normal);
        assert_eq!(report.rx_bytes_delta, 100_000);
        assert_eq!(report.tx_bytes_delta, 50_000);
        assert_eq!(report.rx_errors_delta, 0);
        assert_eq!(report.tx_errors_delta, 0);
    }

    #[test]
    fn test_nic_sample_health_degraded_on_packet_errors() {
        let adapter = NicAdapterInfo {
            name: "Ethernet".into(),
            interface_index: 10,
            description: "Gigabit Ethernet".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        let sample0 = vec![NicRawStats {
            name: "Ethernet".into(),
            received_bytes: 1000,
            sent_bytes: 1000,
            received_discarded: 0,
            received_errors: 0,
            outbound_discarded: 0,
            outbound_errors: 0,
        }];
        let sample1 = vec![NicRawStats {
            name: "Ethernet".into(),
            received_bytes: 2000,
            sent_bytes: 2000,
            received_discarded: 5,
            received_errors: 2,
            outbound_discarded: 0,
            outbound_errors: 0,
        }];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Ethernet"), Duration::from_millis(10))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Degraded);
        assert_eq!(report.rx_discards_delta, 5);
        assert_eq!(report.rx_errors_delta, 2);
    }

    #[test]
    fn test_nic_sample_health_saturation_thresholds() {
        let adapter = NicAdapterInfo {
            name: "VNic".into(),
            interface_index: 2,
            description: "Virtual Adapter".into(),
            status: "Up".into(),
            link_speed_str: "100 Mbps".into(),
            link_speed_bps: 100_000_000,
        };

        // 95 Mbps = 11,875,000 bytes/sec -> saturated
        let (sat_class, _) = evaluate_health_classification(&adapter, 92.5, 10.0, 0, 0, 0, 0);
        assert_eq!(sat_class, NicHealthClassification::Saturated);

        // 75 Mbps = elevated
        let (elev_class, _) = evaluate_health_classification(&adapter, 75.0, 5.0, 0, 0, 0, 0);
        assert_eq!(elev_class, NicHealthClassification::Elevated);

        // 50 Mbps = normal
        let (norm_class, _) = evaluate_health_classification(&adapter, 50.0, 12.0, 0, 0, 0, 0);
        assert_eq!(norm_class, NicHealthClassification::Normal);
    }

    #[test]
    fn test_nic_counter_reset_or_wraparound_handled_safely() {
        let adapter = NicAdapterInfo {
            name: "Wi-Fi".into(),
            interface_index: 16,
            description: "Test".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        // sample0 has 5000, sample1 has 1000 (interface reset)
        let sample0 = vec![NicRawStats {
            name: "Wi-Fi".into(),
            received_bytes: 5000,
            sent_bytes: 5000,
            ..Default::default()
        }];
        let sample1 = vec![NicRawStats {
            name: "Wi-Fi".into(),
            received_bytes: 1000,
            sent_bytes: 1000,
            ..Default::default()
        }];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Wi-Fi"), Duration::from_millis(10))
            .expect("Sampling should succeed without panic");

        assert_eq!(report.rx_bytes_delta, 0);
        assert_eq!(report.tx_bytes_delta, 0);
        assert_eq!(report.classification, NicHealthClassification::Normal);
    }

    #[test]
    fn test_disconnected_adapter_reports_unavailable() {
        let adapter = NicAdapterInfo {
            name: "Ethernet".into(),
            interface_index: 10,
            description: "Unplugged Cable".into(),
            status: "Disconnected".into(),
            link_speed_str: "0 bps".into(),
            link_speed_bps: 0,
        };

        let provider = MockNicProvider::new(vec![adapter], vec![vec![], vec![]]);
        let report = sample_nic_health(&provider, Some("Ethernet"), Duration::from_millis(10))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Unavailable);
    }
}
