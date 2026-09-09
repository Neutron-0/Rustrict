use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use crate::types::{Host, HostStatus};

pub fn render_hosts_table(hosts: &[Host]) {
    if hosts.is_empty() {
        println!("No hosts discovered yet. Run 'scan' to discover devices.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("ID").fg(Color::Cyan),
            Cell::new("IP-Address").fg(Color::Cyan),
            Cell::new("MAC-Address").fg(Color::Cyan),
            Cell::new("Hostname").fg(Color::Cyan),
            Cell::new("Vendor / Hardware").fg(Color::Cyan),
            Cell::new("State").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
        ]);

    for host in hosts {
        let state_cell = if host.online {
            Cell::new("Online").fg(Color::Green)
        } else {
            Cell::new("Offline").fg(Color::DarkGrey)
        };

        let status_cell = match host.status {
            HostStatus::Free => Cell::new("Free").fg(Color::Green),
            HostStatus::Limited(rate, dir) => {
                Cell::new(format!("Limited ({} {})", rate, dir.pretty())).fg(Color::Yellow)
            }
            HostStatus::Blocked(dir) => {
                if host.persistent_block {
                    Cell::new(format!("Blocked [P] ({})", dir.pretty())).fg(Color::Red)
                } else {
                    Cell::new(format!("Blocked ({})", dir.pretty())).fg(Color::Red)
                }
            }
        };

        let hostname_str = if host.name.is_empty() {
            "-".to_string()
        } else {
            host.name.clone()
        };

        let vendor_str = if host.vendor.is_empty() || host.vendor == "Unknown" {
            "-".to_string()
        } else {
            host.vendor.clone()
        };

        table.add_row(Row::from(vec![
            Cell::new(host.id.to_string()),
            Cell::new(host.ip.to_string()),
            Cell::new(host.mac.to_string()),
            Cell::new(hostname_str),
            Cell::new(vendor_str),
            state_cell,
            status_cell,
        ]));
    }

    println!("{table}");
}

pub fn render_services_table(ip: std::net::Ipv4Addr, services: &[crate::core::assessment::ServiceEntry]) {
    if services.is_empty() {
        println!("No open services identified for host {}.", ip);
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Port").fg(Color::Cyan),
            Cell::new("Proto").fg(Color::Cyan),
            Cell::new("Service").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
            Cell::new("Banner / Identification").fg(Color::Cyan),
        ]);

    for s in services {
        let banner_str = s.banner.as_deref().unwrap_or("-");
        table.add_row(Row::from(vec![
            Cell::new(s.port.to_string()).fg(Color::Yellow),
            Cell::new(s.transport.to_uppercase()),
            Cell::new(&s.service_name).fg(Color::Green),
            Cell::new(format!("{:?}", s.status)).fg(Color::Green),
            Cell::new(banner_str),
        ]));
    }

    println!("\nDiscovered Services for {}:", ip);
    println!("{table}\n");
}

pub fn render_findings_table(findings: &[crate::core::assessment::AuditFinding]) {
    if findings.is_empty() {
        println!("No security posture findings recorded.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Severity").fg(Color::Cyan),
            Cell::new("Rule ID").fg(Color::Cyan),
            Cell::new("Target").fg(Color::Cyan),
            Cell::new("Title").fg(Color::Cyan),
            Cell::new("Remediation").fg(Color::Cyan),
        ]);

    for f in findings {
        let (sev_badge, color) = match f.severity {
            crate::core::assessment::AuditSeverity::Critical => ("[CRIT]", Color::Red),
            crate::core::assessment::AuditSeverity::High => ("[HIGH]", Color::Red),
            crate::core::assessment::AuditSeverity::Medium => ("[MED]", Color::Yellow),
            crate::core::assessment::AuditSeverity::Low => ("[LOW]", Color::Blue),
            crate::core::assessment::AuditSeverity::Info => ("[INFO]", Color::Cyan),
        };

        let target_str = if let Some(p) = f.port {
            format!("{}:{}", f.target_ip, p)
        } else {
            f.target_ip.to_string()
        };

        table.add_row(Row::from(vec![
            Cell::new(sev_badge).fg(color),
            Cell::new(&f.rule_id).fg(Color::DarkGrey),
            Cell::new(target_str),
            Cell::new(&f.title),
            Cell::new(&f.remediation).fg(Color::Green),
        ]));
    }

    println!("\nSecurity Posture & Compliance Findings:");
    println!("{table}\n");
}

pub fn render_scope_table(scope: &crate::core::scope::ScopeManager) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Property").fg(Color::Cyan),
            Cell::new("Current Setting").fg(Color::Cyan),
        ]);

    let strict_cell = if scope.strict_mode {
        Cell::new("ENABLED (Non-scoped actions rejected)").fg(Color::Red)
    } else {
        Cell::new("DISABLED (Unrestricted local testing)").fg(Color::Green)
    };

    let allowed_str = if scope.allowed_cidrs.is_empty() {
        "None defined (All subnets accessible if strict mode is disabled)".to_string()
    } else {
        scope
            .allowed_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let excluded_ips_str = if scope.excluded_ips.is_empty() {
        "None".to_string()
    } else {
        scope
            .excluded_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let excluded_macs_str = if scope.excluded_macs.is_empty() {
        "None".to_string()
    } else {
        scope
            .excluded_macs
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    table.add_row(Row::from(vec![Cell::new("Strict Mode"), strict_cell]));
    table.add_row(Row::from(vec![Cell::new("Allowed CIDRs"), Cell::new(allowed_str)]));
    table.add_row(Row::from(vec![Cell::new("Excluded IPs"), Cell::new(excluded_ips_str)]));
    table.add_row(Row::from(vec![Cell::new("Excluded MACs"), Cell::new(excluded_macs_str)]));

    println!("\nOperational Scope Configuration:");
    println!("{table}\n");
}

