use colored::*;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

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
    pub received_bytes: Option<u64>,
    pub sent_bytes: Option<u64>,
    pub received_discarded: Option<u64>,
    pub received_errors: Option<u64>,
    pub outbound_discarded: Option<u64>,
    pub outbound_errors: Option<u64>,
}

impl NicRawStats {
    pub fn new(
        name: impl Into<String>,
        rx_bytes: u64,
        tx_bytes: u64,
        rx_disc: u64,
        rx_err: u64,
        tx_disc: u64,
        tx_err: u64,
    ) -> Self {
        Self {
            name: name.into(),
            received_bytes: Some(rx_bytes),
            sent_bytes: Some(tx_bytes),
            received_discarded: Some(rx_disc),
            received_errors: Some(rx_err),
            outbound_discarded: Some(tx_disc),
            outbound_errors: Some(tx_err),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.received_bytes.is_some()
            && self.sent_bytes.is_some()
            && self.received_discarded.is_some()
            && self.received_errors.is_some()
            && self.outbound_discarded.is_some()
            && self.outbound_errors.is_some()
    }
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
    pub actual_elapsed: Duration,
    pub telemetry_valid: bool,
    pub counter_reset_detected: bool,
    pub rx_rate_bps: Option<u64>,
    pub tx_rate_bps: Option<u64>,
    pub rx_bytes_delta: Option<u64>,
    pub tx_bytes_delta: Option<u64>,
    pub rx_errors_delta: Option<u64>,
    pub tx_errors_delta: Option<u64>,
    pub rx_discards_delta: Option<u64>,
    pub tx_discards_delta: Option<u64>,
    pub rx_utilization_pct: Option<f64>,
    pub tx_utilization_pct: Option<f64>,
    pub classification: NicHealthClassification,
    pub classification_reason: String,
}

/// Abstract telemetry provider to allow testing without invoking live PowerShell.
pub trait NicTelemetryProvider: Send + Sync {
    fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String>;
    fn query_statistics(&self) -> Result<Vec<NicRawStats>, String>;
}

pub struct WindowsPowershellNicProvider {
    pub timeout: Duration,
}

impl Default for WindowsPowershellNicProvider {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

impl WindowsPowershellNicProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

fn run_powershell_bounded(cmd: &str, timeout: Duration) -> Result<std::process::Output, String> {
    let cmd = cmd.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output();
        let _ = tx.send(res);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("Failed to execute PowerShell: {}", e)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(format!("PowerShell command timed out after {:?}", timeout))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("PowerShell execution worker thread disconnected unexpectedly".into())
        }
    }
}

impl NicTelemetryProvider for WindowsPowershellNicProvider {
    fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String> {
        let output = run_powershell_bounded(
            "Get-NetAdapter | Select-Object -Property Name, InterfaceIndex, InterfaceDescription, Status, LinkSpeed | ConvertTo-Csv -NoTypeInformation",
            self.timeout,
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Get-NetAdapter failed: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_adapters_csv(&stdout)
    }

    fn query_statistics(&self) -> Result<Vec<NicRawStats>, String> {
        let output = run_powershell_bounded(
            "Get-NetAdapterStatistics | Select-Object -Property Name, ReceivedBytes, SentBytes, ReceivedDiscardedPackets, ReceivedPacketErrors, OutboundDiscardedPackets, OutboundPacketErrors | ConvertTo-Csv -NoTypeInformation",
            self.timeout,
        )?;

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

    let parse_num = |val: Option<&String>| -> Option<u64> {
        val.and_then(|s| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                t.parse::<u64>().ok()
            }
        })
    };

    let mut stats = Vec::new();
    for line in lines {
        let fields = parse_csv_line(line);
        if fields.is_empty() {
            continue;
        }
        let name = fields[0].clone();
        let received_bytes = parse_num(fields.get(1));
        let sent_bytes = parse_num(fields.get(2));
        let received_discarded = parse_num(fields.get(3));
        let received_errors = parse_num(fields.get(4));
        let outbound_discarded = parse_num(fields.get(5));
        let outbound_errors = parse_num(fields.get(6));

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
        Ok(v) if v >= 0.0 => v,
        _ => return 0,
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
        _ => return 0, // Unrecognized or nonstandard unit treated as unsupported link speed
    };
    (num_val * multiplier) as u64
}

/// Resolves an adapter from a list using exact index, exact name, or substring matching.
/// Returns an error if multiple candidates match ambiguously or none match.
pub fn resolve_adapter<'a>(
    adapters: &'a [NicAdapterInfo],
    filter: Option<&str>,
) -> Result<&'a NicAdapterInfo, String> {
    if adapters.is_empty() {
        return Err("No network adapters detected on the system".into());
    }

    let filter = match filter {
        Some(f) if !f.trim().is_empty() => f.trim(),
        _ => {
            return adapters
                .iter()
                .find(|a| a.status.eq_ignore_ascii_case("Up"))
                .ok_or_else(|| "No active ('Up') network adapter detected".to_string());
        }
    };

    // 1. Exact match on interface_index if filter parses as integer
    if let Ok(idx) = filter.parse::<u32>() {
        let matching: Vec<&NicAdapterInfo> = adapters
            .iter()
            .filter(|a| a.interface_index == idx)
            .collect();
        if matching.len() == 1 {
            return Ok(matching[0]);
        }
    }

    // 2. Exact match on name (case-sensitive)
    let exact_name_matches: Vec<&NicAdapterInfo> =
        adapters.iter().filter(|a| a.name == filter).collect();
    if exact_name_matches.len() == 1 {
        return Ok(exact_name_matches[0]);
    }

    // 3. Case-insensitive exact name match
    let case_name_matches: Vec<&NicAdapterInfo> = adapters
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case(filter))
        .collect();
    if case_name_matches.len() == 1 {
        return Ok(case_name_matches[0]);
    } else if case_name_matches.len() > 1 {
        let names: Vec<String> = case_name_matches
            .iter()
            .map(|a| format!("'{}' (Index {})", a.name, a.interface_index))
            .collect();
        return Err(format!(
            "Ambiguous adapter filter '{}' matched multiple adapters by name: {}. Please specify exact interface name or index.",
            filter,
            names.join(", ")
        ));
    }

    // 4. Substring match on description or name
    let filter_lower = filter.to_ascii_lowercase();
    let partial_matches: Vec<&NicAdapterInfo> = adapters
        .iter()
        .filter(|a| {
            a.name.to_ascii_lowercase().contains(&filter_lower)
                || a.description.to_ascii_lowercase().contains(&filter_lower)
        })
        .collect();

    if partial_matches.len() == 1 {
        Ok(partial_matches[0])
    } else if partial_matches.len() > 1 {
        let matches_desc: Vec<String> = partial_matches
            .iter()
            .map(|a| {
                format!(
                    "'{}' [Index {}, {}]",
                    a.name, a.interface_index, a.description
                )
            })
            .collect();
        Err(format!(
            "Ambiguous adapter filter '{}' matched multiple adapters: {}. Please specify exact interface name or index.",
            filter,
            matches_desc.join("; ")
        ))
    } else {
        Err(format!("No network adapter matched filter '{}'", filter))
    }
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
                "Nominal telemetry: thresholds not crossed ({:.1}% peak utilization, 0 packet errors/discards). Note: Heuristic check does not guarantee hardware health.",
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
    if sample_interval.is_zero() {
        return Err("Sample interval duration cannot be zero".into());
    }
    if sample_interval < Duration::from_millis(5) {
        return Err(format!(
            "Sample interval {:?} is too short (minimum 5ms)",
            sample_interval
        ));
    }

    let adapters = provider.query_adapters()?;
    let adapter = resolve_adapter(&adapters, adapter_filter)?.clone();

    // First sample (t0)
    let t_start = Instant::now();
    let stats0_list = provider.query_statistics()?;
    let stats0_opt = stats0_list
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(&adapter.name));

    sleep(sample_interval);

    // Second sample (t1)
    let stats1_list = provider.query_statistics()?;
    let actual_elapsed = t_start.elapsed();
    let stats1_opt = stats1_list
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(&adapter.name));

    let elapsed_secs = actual_elapsed.as_secs_f64();
    if elapsed_secs <= 0.0 {
        return Err("Clock anomaly: elapsed duration is non-positive".into());
    }

    // Check if adapter statistics are missing entirely
    let (s0, s1) = match (stats0_opt, stats1_opt) {
        (Some(s0), Some(s1)) => (s0, s1),
        _ => {
            return Ok(NicHealthReport {
                adapter: adapter.clone(),
                sample_duration: sample_interval,
                actual_elapsed,
                telemetry_valid: false,
                counter_reset_detected: false,
                rx_rate_bps: None,
                tx_rate_bps: None,
                rx_bytes_delta: None,
                tx_bytes_delta: None,
                rx_errors_delta: None,
                tx_errors_delta: None,
                rx_discards_delta: None,
                tx_discards_delta: None,
                rx_utilization_pct: None,
                tx_utilization_pct: None,
                classification: NicHealthClassification::Unavailable,
                classification_reason: format!(
                    "Driver statistics telemetry missing or unsupported for adapter '{}'",
                    adapter.name
                ),
            });
        }
    };

    // Check if byte counters are present
    let (rx0, rx1, tx0, tx1) = match (
        s0.received_bytes,
        s1.received_bytes,
        s0.sent_bytes,
        s1.sent_bytes,
    ) {
        (Some(r0), Some(r1), Some(t0), Some(t1)) => (r0, r1, t0, t1),
        _ => {
            return Ok(NicHealthReport {
                adapter: adapter.clone(),
                sample_duration: sample_interval,
                actual_elapsed,
                telemetry_valid: false,
                counter_reset_detected: false,
                rx_rate_bps: None,
                tx_rate_bps: None,
                rx_bytes_delta: None,
                tx_bytes_delta: None,
                rx_errors_delta: None,
                tx_errors_delta: None,
                rx_discards_delta: None,
                tx_discards_delta: None,
                rx_utilization_pct: None,
                tx_utilization_pct: None,
                classification: NicHealthClassification::Unavailable,
                classification_reason: format!(
                    "Driver returned incomplete or non-numeric byte counters for adapter '{}'",
                    adapter.name
                ),
            });
        }
    };

    // Monotonic counter decrease check (interface reset or counter wrap)
    if rx1 < rx0 || tx1 < tx0 {
        return Ok(NicHealthReport {
            adapter: adapter.clone(),
            sample_duration: sample_interval,
            actual_elapsed,
            telemetry_valid: false,
            counter_reset_detected: true,
            rx_rate_bps: None,
            tx_rate_bps: None,
            rx_bytes_delta: None,
            tx_bytes_delta: None,
            rx_errors_delta: None,
            tx_errors_delta: None,
            rx_discards_delta: None,
            tx_discards_delta: None,
            rx_utilization_pct: None,
            tx_utilization_pct: None,
            classification: NicHealthClassification::Degraded,
            classification_reason: format!(
                "Monotonic counter reset detected on '{}' during sample window (Rx: {} -> {}, Tx: {} -> {}); throughput metrics invalidated",
                adapter.name, rx0, rx1, tx0, tx1
            ),
        });
    }

    let rx_bytes_delta = rx1 - rx0;
    let tx_bytes_delta = tx1 - tx0;

    let rx_errors_delta = match (s0.received_errors, s1.received_errors) {
        (Some(e0), Some(e1)) if e1 >= e0 => e1 - e0,
        _ => 0,
    };
    let tx_errors_delta = match (s0.outbound_errors, s1.outbound_errors) {
        (Some(e0), Some(e1)) if e1 >= e0 => e1 - e0,
        _ => 0,
    };
    let rx_discards_delta = match (s0.received_discarded, s1.received_discarded) {
        (Some(d0), Some(d1)) if d1 >= d0 => d1 - d0,
        _ => 0,
    };
    let tx_discards_delta = match (s0.outbound_discarded, s1.outbound_discarded) {
        (Some(d0), Some(d1)) if d1 >= d0 => d1 - d0,
        _ => 0,
    };

    let rx_rate_bps = ((rx_bytes_delta as f64 * 8.0) / elapsed_secs) as u64;
    let tx_rate_bps = ((tx_bytes_delta as f64 * 8.0) / elapsed_secs) as u64;

    let (rx_utilization_pct, tx_utilization_pct) = if adapter.link_speed_bps > 0 {
        (
            Some((rx_rate_bps as f64 / adapter.link_speed_bps as f64) * 100.0),
            Some((tx_rate_bps as f64 / adapter.link_speed_bps as f64) * 100.0),
        )
    } else {
        (None, None)
    };

    let (classification, classification_reason) = evaluate_health_classification(
        &adapter,
        rx_utilization_pct.unwrap_or(0.0),
        tx_utilization_pct.unwrap_or(0.0),
        rx_errors_delta,
        tx_errors_delta,
        rx_discards_delta,
        tx_discards_delta,
    );

    Ok(NicHealthReport {
        adapter,
        sample_duration: sample_interval,
        actual_elapsed,
        telemetry_valid: true,
        counter_reset_detected: false,
        rx_rate_bps: Some(rx_rate_bps),
        tx_rate_bps: Some(tx_rate_bps),
        rx_bytes_delta: Some(rx_bytes_delta),
        tx_bytes_delta: Some(tx_bytes_delta),
        rx_errors_delta: Some(rx_errors_delta),
        tx_errors_delta: Some(tx_errors_delta),
        rx_discards_delta: Some(rx_discards_delta),
        tx_discards_delta: Some(tx_discards_delta),
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
        "Sample Window: {:.2}s requested, {:.3}s actual wall-clock",
        report.sample_duration.as_secs_f64(),
        report.actual_elapsed.as_secs_f64(),
    );

    println!("\n{}", "[Measured Telemetry]".bold());
    if report.telemetry_valid {
        let rx_rate_str = report
            .rx_rate_bps
            .map(format_bps)
            .unwrap_or_else(|| "N/A".into());
        let tx_rate_str = report
            .tx_rate_bps
            .map(format_bps)
            .unwrap_or_else(|| "N/A".into());
        let rx_bytes_str = report
            .rx_bytes_delta
            .map(|b| b.to_string())
            .unwrap_or_else(|| "N/A".into());
        let tx_bytes_str = report
            .tx_bytes_delta
            .map(|b| b.to_string())
            .unwrap_or_else(|| "N/A".into());
        let rx_util_str = report
            .rx_utilization_pct
            .map(|u| format!("{:>5.1}%", u))
            .unwrap_or_else(|| "  N/A".into());
        let tx_util_str = report
            .tx_utilization_pct
            .map(|u| format!("{:>5.1}%", u))
            .unwrap_or_else(|| "  N/A".into());
        let rx_disc_str = report
            .rx_discards_delta
            .map(|d| d.to_string())
            .unwrap_or_else(|| "N/A".into());
        let tx_disc_str = report
            .tx_discards_delta
            .map(|d| d.to_string())
            .unwrap_or_else(|| "N/A".into());
        let rx_err_str = report
            .rx_errors_delta
            .map(|e| e.to_string())
            .unwrap_or_else(|| "N/A".into());
        let tx_err_str = report
            .tx_errors_delta
            .map(|e| e.to_string())
            .unwrap_or_else(|| "N/A".into());

        println!(
            "  Rx Rate:    {:>12} ({:>10} bytes)  |  Rx Utilization: {}",
            rx_rate_str, rx_bytes_str, rx_util_str
        );
        println!(
            "  Tx Rate:    {:>12} ({:>10} bytes)  |  Tx Utilization: {}",
            tx_rate_str, tx_bytes_str, tx_util_str
        );
        println!(
            "  Rx Discard: {:>12}  |  Rx Packet Errors: {:>6}",
            rx_disc_str, rx_err_str
        );
        println!(
            "  Tx Discard: {:>12}  |  Tx Packet Errors: {:>6}",
            tx_disc_str, tx_err_str
        );
    } else if report.counter_reset_detected {
        println!(
            "  {}",
            "Counter reset or driver reinitialization detected during sampling."
                .yellow()
                .bold()
        );
        println!("  Measured byte rates invalidated.");
    } else {
        println!(
            "  {}",
            "Telemetry unavailable or incomplete for this adapter.".dimmed()
        );
    }

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

/// Freestanding CLI runner for network adapter health diagnostics.
/// Safe to invoke without admin privileges, WinDivert, or network mutation.
pub fn run_nic_cli<P: NicTelemetryProvider>(
    provider: &P,
    default_iface_name: Option<&str>,
    args: &[&str],
) -> Result<(), String> {
    if args
        .first()
        .map(|s| {
            s.eq_ignore_ascii_case("help")
                || s.eq_ignore_ascii_case("-h")
                || s.eq_ignore_ascii_case("--help")
        })
        .unwrap_or(false)
    {
        println!(
            "{}",
            "Physical Network Adapter Health Diagnostic Commands:"
                .bright_yellow()
                .bold()
        );
        println!("  nic                                 Run 2-second health sampling diagnostic on active adapter");
        println!("  nic status / health / stats [name]  Sample health and metrics for default or named adapter");
        println!("  nic list                            List all detected network adapters and link states");
        println!("  nic <name|index>                    Sample health for specific adapter name or index");
        return Ok(());
    }

    if args
        .first()
        .map(|s| s.eq_ignore_ascii_case("list"))
        .unwrap_or(false)
    {
        let adapters = provider.query_adapters()?;
        println!("\n{}", "Detected Network Adapters:".bold());
        for a in adapters {
            let status_styled = if a.status.eq_ignore_ascii_case("Up") {
                a.status.green().bold()
            } else {
                a.status.dimmed()
            };
            println!(
                "  [{:>2}] {:<24} Status: {:<12} Link: {:<10} ({})",
                a.interface_index,
                a.name.bold(),
                status_styled,
                a.link_speed_str,
                a.description
            );
        }
        println!();
        return Ok(());
    }

    let mut filter: Option<&str> = None;
    if let Some(first) = args.first() {
        if first.eq_ignore_ascii_case("status")
            || first.eq_ignore_ascii_case("health")
            || first.eq_ignore_ascii_case("stats")
        {
            if let Some(second) = args.get(1) {
                filter = Some(*second);
            }
        } else {
            filter = Some(*first);
        }
    }

    let adapter_filter = filter.or(default_iface_name);
    let target_str = adapter_filter.unwrap_or("active adapter");
    println!(
        "{}",
        format!(
            "Sampling network adapter telemetry for '{}' (2-second interval)...",
            target_str
        )
        .cyan()
    );

    let report = sample_nic_health(provider, adapter_filter, Duration::from_secs(2))?;

    print_nic_report(&report);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct MockNicProvider {
        pub adapters: Vec<NicAdapterInfo>,
        pub stats_samples: Arc<parking_lot::Mutex<Vec<Vec<NicRawStats>>>>,
        pub stats_calls: Arc<AtomicUsize>,
    }

    impl MockNicProvider {
        pub fn new(adapters: Vec<NicAdapterInfo>, samples: Vec<Vec<NicRawStats>>) -> Self {
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
        assert_eq!(parse_link_speed_to_bps("unknown_unit"), 0);
        assert_eq!(parse_link_speed_to_bps("-10 Mbps"), 0);
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
    fn test_parse_statistics_csv_missing_and_nonnumeric_values() {
        let csv = r#""Name","ReceivedBytes","SentBytes","ReceivedDiscardedPackets","ReceivedPacketErrors","OutboundDiscardedPackets","OutboundPacketErrors"
"Wi-Fi","1000","2000","0","0","0","0"
"VirtualNet","","N/A","0","0","0","0"
"#;
        let stats = parse_statistics_csv(csv).unwrap();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].received_bytes, Some(1000));
        assert_eq!(stats[0].sent_bytes, Some(2000));
        assert!(stats[0].is_complete());

        assert_eq!(stats[1].name, "VirtualNet");
        assert_eq!(stats[1].received_bytes, None);
        assert_eq!(stats[1].sent_bytes, None);
        assert!(!stats[1].is_complete());
    }

    #[test]
    fn test_resolve_adapter_precedence_and_ambiguity() {
        let adapters = vec![
            NicAdapterInfo {
                name: "Wi-Fi".into(),
                interface_index: 16,
                description: "MediaTek Wi-Fi 6E Controller".into(),
                status: "Up".into(),
                link_speed_str: "1.2 Gbps".into(),
                link_speed_bps: 1_200_000_000,
            },
            NicAdapterInfo {
                name: "Ethernet 1".into(),
                interface_index: 10,
                description: "Realtek Gaming Controller".into(),
                status: "Disconnected".into(),
                link_speed_str: "0 bps".into(),
                link_speed_bps: 0,
            },
            NicAdapterInfo {
                name: "Ethernet 2".into(),
                interface_index: 11,
                description: "Realtek Secondary Controller".into(),
                status: "Up".into(),
                link_speed_str: "1 Gbps".into(),
                link_speed_bps: 1_000_000_000,
            },
        ];

        // 1. Index match
        let by_idx = resolve_adapter(&adapters, Some("10")).unwrap();
        assert_eq!(by_idx.name, "Ethernet 1");

        // 2. Exact name match
        let by_name = resolve_adapter(&adapters, Some("Wi-Fi")).unwrap();
        assert_eq!(by_name.interface_index, 16);

        // 3. Ambiguous substring match returns error
        let amb = resolve_adapter(&adapters, Some("Realtek"));
        assert!(amb.is_err());
        assert!(amb.unwrap_err().contains("matched multiple adapters"));

        // 4. Default without filter picks first 'Up'
        let default_up = resolve_adapter(&adapters, None).unwrap();
        assert_eq!(default_up.name, "Wi-Fi");

        // 5. Non-existent filter returns error
        let none_match = resolve_adapter(&adapters, Some("NonExistentAdapter"));
        assert!(none_match.is_err());
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

        let sample0 = vec![NicRawStats::new("Wi-Fi", 10_000_000, 2_000_000, 0, 0, 0, 0)];
        let sample1 = vec![NicRawStats::new("Wi-Fi", 10_100_000, 2_050_000, 0, 0, 0, 0)];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Wi-Fi"), Duration::from_millis(50))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Normal);
        assert!(report.telemetry_valid);
        assert!(!report.counter_reset_detected);
        assert_eq!(report.rx_bytes_delta, Some(100_000));
        assert_eq!(report.tx_bytes_delta, Some(50_000));
        assert_eq!(report.rx_errors_delta, Some(0));
        assert_eq!(report.tx_errors_delta, Some(0));
        assert!(report.actual_elapsed >= Duration::from_millis(45));
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

        let sample0 = vec![NicRawStats::new("Ethernet", 1000, 1000, 0, 0, 0, 0)];
        let sample1 = vec![NicRawStats::new("Ethernet", 2000, 2000, 5, 2, 0, 0)];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Ethernet"), Duration::from_millis(10))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Degraded);
        assert!(report.telemetry_valid);
        assert_eq!(report.rx_discards_delta, Some(5));
        assert_eq!(report.rx_errors_delta, Some(2));
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

        let (sat_class, _) = evaluate_health_classification(&adapter, 92.5, 10.0, 0, 0, 0, 0);
        assert_eq!(sat_class, NicHealthClassification::Saturated);

        let (elev_class, _) = evaluate_health_classification(&adapter, 75.0, 5.0, 0, 0, 0, 0);
        assert_eq!(elev_class, NicHealthClassification::Elevated);

        let (norm_class, _) = evaluate_health_classification(&adapter, 50.0, 12.0, 0, 0, 0, 0);
        assert_eq!(norm_class, NicHealthClassification::Normal);
    }

    #[test]
    fn test_nic_counter_reset_treated_as_invalidation_and_degraded() {
        let adapter = NicAdapterInfo {
            name: "Wi-Fi".into(),
            interface_index: 16,
            description: "Test".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        // sample0 has 5000, sample1 has 1000 (interface reset / counter wrap)
        let sample0 = vec![NicRawStats::new("Wi-Fi", 5000, 5000, 0, 0, 0, 0)];
        let sample1 = vec![NicRawStats::new("Wi-Fi", 1000, 1000, 0, 0, 0, 0)];

        let provider = MockNicProvider::new(vec![adapter], vec![sample0, sample1]);
        let report = sample_nic_health(&provider, Some("Wi-Fi"), Duration::from_millis(10))
            .expect("Sampling should succeed");

        assert!(report.counter_reset_detected);
        assert!(!report.telemetry_valid);
        assert_eq!(report.rx_bytes_delta, None);
        assert_eq!(report.tx_bytes_delta, None);
        assert_eq!(report.classification, NicHealthClassification::Degraded);
        assert!(report.classification_reason.contains("counter reset"));
    }

    #[test]
    fn test_missing_statistics_reported_unavailable_not_zero_normal() {
        let adapter = NicAdapterInfo {
            name: "Wi-Fi".into(),
            interface_index: 16,
            description: "Active Adapter with Missing Telemetry".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        // Driver returns empty statistics list
        let provider = MockNicProvider::new(vec![adapter], vec![vec![], vec![]]);
        let report = sample_nic_health(&provider, Some("Wi-Fi"), Duration::from_millis(10))
            .expect("Sampling should succeed");

        assert_eq!(report.classification, NicHealthClassification::Unavailable);
        assert!(!report.telemetry_valid);
        assert_eq!(report.rx_bytes_delta, None);
        assert!(report
            .classification_reason
            .contains("missing or unsupported"));
    }

    #[test]
    fn test_zero_duration_sampling_rejected() {
        let adapter = NicAdapterInfo {
            name: "Wi-Fi".into(),
            interface_index: 16,
            description: "Test".into(),
            status: "Up".into(),
            link_speed_str: "1 Gbps".into(),
            link_speed_bps: 1_000_000_000,
        };

        let provider = MockNicProvider::new(vec![adapter], vec![vec![], vec![]]);
        let res = sample_nic_health(&provider, Some("Wi-Fi"), Duration::ZERO);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("cannot be zero"));
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
