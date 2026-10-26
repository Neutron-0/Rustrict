use crate::types::{Host, HostStatus};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};

pub fn render_hosts_table(hosts: &[Host]) {
    if hosts.is_empty() {
        println!("No hosts discovered yet. Run 'scan' to discover devices.");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
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

pub fn render_services_table(
    ip: std::net::Ipv4Addr,
    services: &[crate::core::assessment::ServiceEntry],
) {
    if services.is_empty() {
        println!("No open services identified for host {}.", ip);
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
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
    table.load_preset(UTF8_FULL).set_header(vec![
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
    table.load_preset(UTF8_FULL).set_header(vec![
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
    table.add_row(Row::from(vec![
        Cell::new("Allowed CIDRs"),
        Cell::new(allowed_str),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Excluded IPs"),
        Cell::new(excluded_ips_str),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Excluded MACs"),
        Cell::new(excluded_macs_str),
    ]));

    println!("\nOperational Scope Configuration:");
    println!("{table}\n");
}

pub fn render_router_capabilities_table(caps: &crate::gateway::admin::RouterCapabilityMatrix) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Administrative Feature / Capability").fg(Color::Cyan),
        Cell::new("Classification Status").fg(Color::Cyan),
        Cell::new("Operational").fg(Color::Cyan),
    ]);

    let row = |name: &str, status: &crate::gateway::admin::CapabilityClassification| {
        let op_cell = if status.is_operational() {
            Cell::new("YES").fg(Color::Green)
        } else {
            Cell::new("NO").fg(Color::DarkGrey)
        };
        let status_color = match status {
            crate::gateway::admin::CapabilityClassification::Implemented
            | crate::gateway::admin::CapabilityClassification::UnitTested
            | crate::gateway::admin::CapabilityClassification::LabVerified
            | crate::gateway::admin::CapabilityClassification::RouterVerified => Color::Green,
            crate::gateway::admin::CapabilityClassification::Conditional(_) => Color::Yellow,
            crate::gateway::admin::CapabilityClassification::NotImplemented => Color::Red,
            crate::gateway::admin::CapabilityClassification::Unknown(_) => Color::Magenta,
        };
        Row::from(vec![
            Cell::new(name),
            Cell::new(status.to_string()).fg(status_color),
            op_cell,
        ])
    };

    table.add_row(row(
        "Read-only Gateway Discovery (SSDP / Description)",
        &caps.read_only_discovery,
    ));
    table.add_row(row(
        "Authoritative Host Inventory (DHCP Leases)",
        &caps.host_inventory,
    ));
    table.add_row(row(
        "Device Interface Identification (Wi-Fi vs Ethernet)",
        &caps.device_identification_interface_type,
    ));
    table.add_row(row(
        "IPv4 Access Policy Enforcement",
        &caps.ipv4_policy_enforcement,
    ));
    table.add_row(row(
        "IPv6 Access Policy Enforcement (Dual-Stack)",
        &caps.ipv6_policy_enforcement,
    ));
    table.add_row(row(
        "Per-Device Selective Client Access Control",
        &caps.per_device_access_policy,
    ));
    table.add_row(row(
        "Network-Wide Global WAN Access Control",
        &caps.network_wide_access_policy,
    ));
    table.add_row(row(
        "Authenticated Router Management Protocols",
        &caps.authenticated_admin_interfaces,
    ));
    table.add_row(row(
        "Timed Policy with Guaranteed Auto-Recovery",
        &caps.timed_policy_auto_recovery,
    ));
    table.add_row(row(
        "Policy Persistence Across App Exit",
        &caps.persistence_after_app_exit,
    ));
    table.add_row(row(
        "Policy Persistence Across Host PC Shutdown",
        &caps.persistence_after_host_shutdown,
    ));

    println!("\nRouter Administration Capability Discovery Matrix:");
    println!("{table}\n");
}

pub fn render_router_plan_preview(plan: &crate::gateway::admin::OperationPlan) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Dry-Run Plan Field").fg(Color::Cyan),
        Cell::new("Details & Specifications").fg(Color::Cyan),
    ]);

    table.add_row(Row::from(vec![
        Cell::new("Execution Mode"),
        Cell::new("DRY-RUN (Zero Network Traffic / No Changes Applied)").fg(Color::Green),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Provider"),
        Cell::new(&plan.provider_name).fg(Color::Yellow),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Router Identity"),
        Cell::new(plan.router_identity.display_summary()),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Target Scope"),
        Cell::new(plan.target_scope.to_string()),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Target Devices Count"),
        Cell::new(if plan.target_count == 0 {
            "All Network Devices (Global)".to_string()
        } else {
            plan.target_count.to_string()
        }),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Policy Duration"),
        Cell::new(plan.duration.to_string()),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Policy Persistence"),
        Cell::new(plan.persistence.to_string()),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Authentication Status"),
        if plan.auth_established {
            Cell::new(format!("AUTHENTICATED ({})", plan.required_auth)).fg(Color::Green)
        } else {
            Cell::new(format!("NOT AUTHENTICATED ({})", plan.required_auth)).fg(Color::Red)
        },
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Expected WAN Impact"),
        Cell::new(&plan.expected_wan_impact).fg(Color::Yellow),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Expected LAN Impact"),
        Cell::new(&plan.expected_lan_impact).fg(Color::Green),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Management Plane Safety"),
        if plan.management_plane_safe {
            Cell::new("GUARANTEED (Router HTTP/HTTPS Port 80/443 Remains Open)").fg(Color::Green)
        } else {
            Cell::new("RISK OF LOCKOUT").fg(Color::Red)
        },
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Recovery Mechanism"),
        Cell::new(&plan.recovery_mechanism).fg(Color::Cyan),
    ]));

    let risks_str = if plan.uncertainties_and_risks.is_empty() {
        "None identified".to_string()
    } else {
        plan.uncertainties_and_risks
            .iter()
            .map(|r| format!("• {}", r))
            .collect::<Vec<_>>()
            .join("\n")
    };
    table.add_row(Row::from(vec![
        Cell::new("Risks & Uncertainties"),
        Cell::new(risks_str).fg(Color::Magenta),
    ]));

    println!("\nAdministrative Policy Dry-Run Preview:");
    println!("{table}\n");
}

pub fn render_router_policies_table(policies: &[crate::gateway::admin::ActivePolicyStatus]) {
    if policies.is_empty() {
        println!("\nNo active router-enforced policies currently registered.\n");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Policy ID").fg(Color::Cyan),
        Cell::new("Provider / Target").fg(Color::Cyan),
        Cell::new("Target Scope").fg(Color::Cyan),
        Cell::new("Enforcement Point").fg(Color::Cyan),
        Cell::new("Persistence").fg(Color::Cyan),
        Cell::new("Autonomous Recovery").fg(Color::Cyan),
        Cell::new("Expiry / Duration").fg(Color::Cyan),
        Cell::new("Lifecycle State").fg(Color::Cyan),
    ]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for p in policies {
        let expiry_str = if let Some(exp) = p.expires_at_unix {
            if now >= exp {
                "Expired".to_string()
            } else {
                let remaining = exp - now;
                format!("{:.1}m remaining", remaining as f64 / 60.0)
            }
        } else {
            "Indefinite".to_string()
        };

        let state_cell = match &p.lifecycle_state {
            crate::gateway::admin::PolicyLifecycleState::Active => {
                if let Some(exp) = p.expires_at_unix {
                    if now >= exp {
                        Cell::new("EXPIRED (Pending Recovery)").fg(Color::Red)
                    } else {
                        Cell::new("ACTIVE (Timed)").fg(Color::Green)
                    }
                } else {
                    Cell::new("ACTIVE (Indefinite)").fg(Color::Yellow)
                }
            }
            crate::gateway::admin::PolicyLifecycleState::Planned => {
                Cell::new("PLANNED").fg(Color::Cyan)
            }
            crate::gateway::admin::PolicyLifecycleState::PendingApplication => {
                Cell::new("PENDING APPLICATION").fg(Color::Cyan)
            }
            crate::gateway::admin::PolicyLifecycleState::ExpiredPendingRecovery => {
                Cell::new("EXPIRED (Pending Recovery)").fg(Color::Red)
            }
            crate::gateway::admin::PolicyLifecycleState::RecoveryInProgress => {
                Cell::new("RECOVERY IN PROGRESS").fg(Color::Yellow)
            }
            crate::gateway::admin::PolicyLifecycleState::Recovered => {
                Cell::new("RECOVERED").fg(Color::Green)
            }
            crate::gateway::admin::PolicyLifecycleState::Failed(err) => {
                Cell::new(format!("FAILED: {}", err)).fg(Color::Red)
            }
            crate::gateway::admin::PolicyLifecycleState::PartialFailure {
                failed_target,
                rollback_errors,
                ..
            } => {
                if rollback_errors.is_empty() {
                    Cell::new(format!("FAILED: {} (Rolled back)", failed_target)).fg(Color::Red)
                } else {
                    Cell::new(format!(
                        "CRITICAL PARTIAL FAILURE: {} (Rollback failed)",
                        failed_target
                    ))
                    .fg(Color::Red)
                }
            }
            crate::gateway::admin::PolicyLifecycleState::Unknown => {
                let desc = p.last_error.as_deref().unwrap_or("Unverified local state");
                Cell::new(format!("UNKNOWN ({})", desc)).fg(Color::Magenta)
            }
        };

        let persist_str = if p.is_persistent {
            "Router NVRAM / Storage"
        } else {
            "Volatile Session"
        };

        let auto_rec_cell = if p.autonomous_recovery {
            Cell::new("YES (Router Watchdog)").fg(Color::Green)
        } else {
            Cell::new("NO (Manual / External)").fg(Color::Yellow)
        };

        let provider_str = p.provider_name.as_deref().unwrap_or("Standard Router");

        table.add_row(Row::from(vec![
            Cell::new(&p.policy_id).fg(Color::White),
            Cell::new(provider_str),
            Cell::new(p.scope.to_string()),
            Cell::new(&p.enforcement_point),
            Cell::new(persist_str),
            auto_rec_cell,
            Cell::new(expiry_str),
            state_cell,
        ]));
    }

    println!("\nActive Router-Enforced Policies:");
    println!("{table}\n");
}

pub fn render_router_unified_policies_table(
    policies: &[crate::gateway::admin::UnifiedPolicyEntry],
) {
    if policies.is_empty() {
        println!("\nNo router-enforced policies currently registered or recorded.\n");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Policy ID").fg(Color::Cyan),
        Cell::new("Provider").fg(Color::Cyan),
        Cell::new("Target Scope").fg(Color::Cyan),
        Cell::new("Lifecycle State").fg(Color::Cyan),
        Cell::new("Duration / Expiry").fg(Color::Cyan),
        Cell::new("Recovery Status").fg(Color::Cyan),
        Cell::new("Confirmation Source").fg(Color::Cyan),
        Cell::new("Last Result").fg(Color::Cyan),
    ]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for p in policies {
        let (lifecycle_text, lifecycle_color) = match &p.lifecycle_state {
            crate::gateway::admin::PolicyLifecycleState::Active => {
                if let Some(exp) = p.expires_at_unix {
                    if now >= exp {
                        ("EXPIRED (Pending Recovery)".to_string(), Color::Red)
                    } else {
                        ("ACTIVE (Timed)".to_string(), Color::Green)
                    }
                } else {
                    ("ACTIVE (Indefinite)".to_string(), Color::Green)
                }
            }
            crate::gateway::admin::PolicyLifecycleState::Planned => {
                ("PLANNED".to_string(), Color::Cyan)
            }
            crate::gateway::admin::PolicyLifecycleState::PendingApplication => {
                ("PENDING APPLICATION".to_string(), Color::Cyan)
            }
            crate::gateway::admin::PolicyLifecycleState::ExpiredPendingRecovery => {
                ("EXPIRED (Pending Recovery)".to_string(), Color::Red)
            }
            crate::gateway::admin::PolicyLifecycleState::RecoveryInProgress => {
                ("RECOVERY IN PROGRESS".to_string(), Color::Yellow)
            }
            crate::gateway::admin::PolicyLifecycleState::Recovered => {
                ("RECOVERED".to_string(), Color::Cyan)
            }
            crate::gateway::admin::PolicyLifecycleState::Failed(err) => {
                let s = if err.len() > 30 {
                    format!("FAILED: {}...", &err[..27])
                } else {
                    format!("FAILED: {}", err)
                };
                (s, Color::Red)
            }
            crate::gateway::admin::PolicyLifecycleState::PartialFailure {
                failed_target,
                rollback_errors,
                ..
            } => {
                let s = if rollback_errors.is_empty() {
                    format!("PARTIAL FAIL: {} (Rolled back)", failed_target)
                } else {
                    format!("CRITICAL: {} (Rollback failed)", failed_target)
                };
                (s, Color::Red)
            }
            crate::gateway::admin::PolicyLifecycleState::Unknown => {
                ("UNKNOWN (Unverified)".to_string(), Color::Magenta)
            }
        };

        let duration_str = match &p.duration {
            crate::gateway::admin::PolicyDuration::Indefinite => "Indefinite".to_string(),
            crate::gateway::admin::PolicyDuration::Temporary(dur) => {
                if let Some(exp) = p.expires_at_unix {
                    if now >= exp {
                        format!("Temporary ({}s, Expired)", dur.as_secs())
                    } else {
                        let remaining = exp - now;
                        format!(
                            "Temporary ({}s, {:.1}m rem)",
                            dur.as_secs(),
                            remaining as f64 / 60.0
                        )
                    }
                } else {
                    format!("Temporary ({}s)", dur.as_secs())
                }
            }
        };

        let (rec_text, rec_color) = match &p.recovery_status {
            crate::gateway::admin::PolicyRecoveryStatus::Unsupported => {
                ("Unsupported".to_string(), Color::DarkGrey)
            }
            crate::gateway::admin::PolicyRecoveryStatus::NotApplicable => {
                ("N/A (Indefinite)".to_string(), Color::DarkGrey)
            }
            crate::gateway::admin::PolicyRecoveryStatus::Pending => {
                ("Pending".to_string(), Color::Yellow)
            }
            crate::gateway::admin::PolicyRecoveryStatus::InstalledAndConfirmed(mech) => {
                (format!("Confirmed ({})", mech), Color::Green)
            }
            crate::gateway::admin::PolicyRecoveryStatus::Failed(err) => {
                let s = if err.len() > 25 {
                    format!("Failed: {}...", &err[..22])
                } else {
                    format!("Failed: {}", err)
                };
                (s, Color::Red)
            }
            crate::gateway::admin::PolicyRecoveryStatus::UnknownOrUnverified => {
                ("Unknown / Unverified".to_string(), Color::Magenta)
            }
        };

        let (conf_text, conf_color) = match p.confirmation_state {
            crate::gateway::admin::PolicyConfirmationState::ProviderConfirmed => {
                ("Provider Confirmed (Live)", Color::Green)
            }
            crate::gateway::admin::PolicyConfirmationState::LocallyRecordedUnverified => {
                ("Local Record (Unverified)", Color::Yellow)
            }
            crate::gateway::admin::PolicyConfirmationState::LocallyRecordedRecovered => {
                ("Local Record (Recovered)", Color::Cyan)
            }
            crate::gateway::admin::PolicyConfirmationState::LocallyRecordedFailed => {
                ("Local Record (Failed)", Color::Red)
            }
        };

        let last_res = p.last_execution_result.as_deref().unwrap_or("None");

        let prov_str = format!("{} ({})", p.provider_name, p.provider_id);

        table.add_row(Row::from(vec![
            Cell::new(&p.policy_id).fg(Color::White),
            Cell::new(prov_str),
            Cell::new(p.scope.to_string()),
            Cell::new(lifecycle_text).fg(lifecycle_color),
            Cell::new(duration_str),
            Cell::new(rec_text).fg(rec_color),
            Cell::new(conf_text).fg(conf_color),
            Cell::new(last_res),
        ]));
    }

    println!("\nUnified Router-Enforced Policies:");
    println!("{table}\n");
}

pub fn render_router_policy_detail(detail: &crate::gateway::admin::PolicyDetailView) {
    let p = &detail.policy;
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Policy Specification Field").fg(Color::Cyan),
        Cell::new("Current Configuration & Inspection Value").fg(Color::Cyan),
    ]);

    table.add_row(Row::from(vec![
        Cell::new("Policy ID"),
        Cell::new(&p.policy_id).fg(Color::White),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Provider"),
        Cell::new(format!("{} (ID: {})", p.provider_name, p.provider_id)).fg(Color::Yellow),
    ]));
    if let Some(router_id) = &detail.router_identity {
        table.add_row(Row::from(vec![
            Cell::new("Router Identity"),
            Cell::new(router_id),
        ]));
    }
    table.add_row(Row::from(vec![
        Cell::new("Target Scope"),
        Cell::new(p.scope.to_string()),
    ]));
    table.add_row(Row::from(vec![
        Cell::new("Enforcement Point"),
        Cell::new(&p.enforcement_point),
    ]));

    let duration_str = match &p.duration {
        crate::gateway::admin::PolicyDuration::Indefinite => {
            "Indefinite (Manual resume required)".to_string()
        }
        crate::gateway::admin::PolicyDuration::Temporary(dur) => {
            format!("Temporary ({} seconds)", dur.as_secs())
        }
    };
    table.add_row(Row::from(vec![
        Cell::new("Duration"),
        Cell::new(duration_str),
    ]));

    let persist_str = if p.is_persistent {
        "Router Storage NVRAM (Survives controller exits & router reboots)"
    } else {
        "Volatile Session (Discarded on controller exit or router reboot)"
    };
    table.add_row(Row::from(vec![
        Cell::new("Persistence"),
        Cell::new(persist_str),
    ]));

    table.add_row(Row::from(vec![
        Cell::new("Applied At"),
        Cell::new(format!("Unix timestamp {}", p.applied_at_unix)),
    ]));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expiry_str = if let Some(exp) = p.expires_at_unix {
        if now >= exp {
            format!("Unix timestamp {} (EXPIRED {} seconds ago)", exp, now - exp)
        } else {
            let rem = exp - now;
            format!(
                "Unix timestamp {} ({:.1} minutes remaining)",
                exp,
                rem as f64 / 60.0
            )
        }
    } else {
        "None (Indefinite policy)".to_string()
    };
    table.add_row(Row::from(vec![
        Cell::new("Expiration Time"),
        Cell::new(expiry_str),
    ]));

    let (lifecycle_text, lifecycle_color) = match &p.lifecycle_state {
        crate::gateway::admin::PolicyLifecycleState::Active => {
            ("ACTIVE (Enforced on Router)".to_string(), Color::Green)
        }
        crate::gateway::admin::PolicyLifecycleState::Planned => {
            ("PLANNED".to_string(), Color::Cyan)
        }
        crate::gateway::admin::PolicyLifecycleState::PendingApplication => {
            ("PENDING APPLICATION".to_string(), Color::Cyan)
        }
        crate::gateway::admin::PolicyLifecycleState::ExpiredPendingRecovery => {
            ("EXPIRED (Pending Recovery)".to_string(), Color::Red)
        }
        crate::gateway::admin::PolicyLifecycleState::RecoveryInProgress => {
            ("RECOVERY IN PROGRESS".to_string(), Color::Yellow)
        }
        crate::gateway::admin::PolicyLifecycleState::Recovered => {
            ("RECOVERED".to_string(), Color::Cyan)
        }
        crate::gateway::admin::PolicyLifecycleState::Failed(err) => {
            (format!("FAILED: {}", err), Color::Red)
        }
        crate::gateway::admin::PolicyLifecycleState::PartialFailure {
            failed_target,
            rollback_errors,
            ..
        } => {
            if rollback_errors.is_empty() {
                (
                    format!(
                        "PARTIAL FAILURE: {} (All prior rules rolled back)",
                        failed_target
                    ),
                    Color::Red,
                )
            } else {
                (
                    format!(
                        "CRITICAL PARTIAL FAILURE: {} (ROLLBACK FAILED: {:?})",
                        failed_target, rollback_errors
                    ),
                    Color::Red,
                )
            }
        }
        crate::gateway::admin::PolicyLifecycleState::Unknown => (
            "UNKNOWN (Unverified local state)".to_string(),
            Color::Magenta,
        ),
    };
    table.add_row(Row::from(vec![
        Cell::new("Lifecycle State"),
        Cell::new(lifecycle_text).fg(lifecycle_color),
    ]));

    let (conf_text, conf_color) = match p.confirmation_state {
        crate::gateway::admin::PolicyConfirmationState::ProviderConfirmed => {
            ("Provider Confirmed (Verified on live router)", Color::Green)
        }
        crate::gateway::admin::PolicyConfirmationState::LocallyRecordedUnverified => (
            "Locally Recorded (Unverified against router hardware)",
            Color::Yellow,
        ),
        crate::gateway::admin::PolicyConfirmationState::LocallyRecordedRecovered => (
            "Locally Recorded (Recovered / verified absent from router)",
            Color::Cyan,
        ),
        crate::gateway::admin::PolicyConfirmationState::LocallyRecordedFailed => {
            ("Locally Recorded (Execution failed)", Color::Red)
        }
    };
    table.add_row(Row::from(vec![
        Cell::new("Confirmation State"),
        Cell::new(conf_text).fg(conf_color),
    ]));

    let verify_color = if detail.provider_verification_available {
        Color::Green
    } else {
        Color::Yellow
    };
    table.add_row(Row::from(vec![
        Cell::new("Live Router Verification"),
        Cell::new(&detail.provider_verification_status).fg(verify_color),
    ]));

    let (rec_text, rec_color) = match &p.recovery_status {
        crate::gateway::admin::PolicyRecoveryStatus::Unsupported => {
            ("Unsupported by Provider".to_string(), Color::DarkGrey)
        }
        crate::gateway::admin::PolicyRecoveryStatus::NotApplicable => (
            "Not Applicable (Indefinite Policy)".to_string(),
            Color::DarkGrey,
        ),
        crate::gateway::admin::PolicyRecoveryStatus::Pending => {
            ("Pending Installation".to_string(), Color::Yellow)
        }
        crate::gateway::admin::PolicyRecoveryStatus::InstalledAndConfirmed(mech) => {
            (format!("Confirmed Installed ({})", mech), Color::Green)
        }
        crate::gateway::admin::PolicyRecoveryStatus::Failed(err) => {
            (format!("Failed: {}", err), Color::Red)
        }
        crate::gateway::admin::PolicyRecoveryStatus::UnknownOrUnverified => {
            ("Unknown / Unverified".to_string(), Color::Magenta)
        }
    };
    table.add_row(Row::from(vec![
        Cell::new("Autonomous Recovery"),
        Cell::new(rec_text).fg(rec_color),
    ]));

    table.add_row(Row::from(vec![
        Cell::new("Last Execution Result"),
        Cell::new(p.last_execution_result.as_deref().unwrap_or("None")),
    ]));

    println!("\nDetailed Router Policy Inspection:");
    println!("{table}\n");

    // Historical Lifecycle Transitions & Execution Audit Timeline
    if detail.audit_events.is_empty() {
        println!("Lifecycle Event Timeline: Unavailable (no local audit execution records found for this policy ID).\n");
    } else {
        println!(
            "Historical Lifecycle Transitions & Execution Audit Timeline ({} event(s)):",
            detail.audit_events.len()
        );
        let mut hist_table = Table::new();
        hist_table.load_preset(UTF8_FULL).set_header(vec![
            Cell::new("Timestamp (Unix)").fg(Color::Cyan),
            Cell::new("Operation").fg(Color::Cyan),
            Cell::new("State Transition").fg(Color::Cyan),
            Cell::new("Duration").fg(Color::Cyan),
            Cell::new("Persistence").fg(Color::Cyan),
            Cell::new("Result / Status").fg(Color::Cyan),
        ]);

        for ev in &detail.audit_events {
            let transition = format!("{} -> {}", ev.initial_state, ev.final_state);
            let (res_text, res_color) = if let Some(err) = &ev.error {
                (format!("FAILED: {}", err), Color::Red)
            } else {
                ("Success".to_string(), Color::Green)
            };

            hist_table.add_row(Row::from(vec![
                Cell::new(ev.timestamp_unix.to_string()),
                Cell::new(&ev.operation),
                Cell::new(transition),
                Cell::new(ev.duration.to_string()),
                Cell::new(ev.persistence.to_string()),
                Cell::new(res_text).fg(res_color),
            ]));
        }
        println!("{hist_table}\n");
    }
}

pub fn render_router_providers_table(
    providers: &[crate::gateway::admin::ProviderDescriptor],
    active_id: Option<&str>,
) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Status").fg(Color::Cyan),
        Cell::new("Provider ID").fg(Color::Cyan),
        Cell::new("Display Name").fg(Color::Cyan),
        Cell::new("Vendor").fg(Color::Cyan),
        Cell::new("Protocols / Transport").fg(Color::Cyan),
        Cell::new("Default Port").fg(Color::Cyan),
        Cell::new("Autonomous Recovery").fg(Color::Cyan),
    ]);

    for p in providers {
        let is_active = active_id.map(|id| id == p.id).unwrap_or(false);
        let status_cell = if is_active {
            Cell::new("* CONNECTED").fg(Color::Green)
        } else {
            Cell::new("-").fg(Color::DarkGrey)
        };

        let port_str = if p.default_port == 0 {
            "N/A".to_string()
        } else {
            p.default_port.to_string()
        };

        let recovery_color = if p.autonomous_recovery_support.starts_with("Full")
            || p.autonomous_recovery_support.starts_with("Simulated")
        {
            Color::Green
        } else {
            Color::Yellow
        };

        table.add_row(Row::from(vec![
            status_cell,
            Cell::new(&p.id).fg(Color::White),
            Cell::new(&p.name),
            Cell::new(&p.vendor),
            Cell::new(&p.protocols),
            Cell::new(port_str),
            Cell::new(&p.autonomous_recovery_support).fg(recovery_color),
        ]));
    }

    println!("\nSupported Router Administration Providers:");
    println!("{table}\n");
}

pub fn render_router_history_table(records: &[crate::gateway::admin::PolicyExecutionRecord]) {
    if records.is_empty() {
        println!("\nNo historical router policy execution records found in persistent state.\n");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Timestamp (Unix)").fg(Color::Cyan),
        Cell::new("Execution ID").fg(Color::Cyan),
        Cell::new("Provider").fg(Color::Cyan),
        Cell::new("Operation").fg(Color::Cyan),
        Cell::new("Target Scope").fg(Color::Cyan),
        Cell::new("State Transition").fg(Color::Cyan),
        Cell::new("Recovery").fg(Color::Cyan),
        Cell::new("Status / Details").fg(Color::Cyan),
    ]);

    for r in records {
        let transition = format!("{} -> {}", r.initial_state, r.final_state);
        let recovery_cell = if r.autonomous_recovery_guaranteed {
            Cell::new("Guaranteed").fg(Color::Green)
        } else {
            Cell::new("None / Manual").fg(Color::Yellow)
        };

        let (status_str, status_color) = if let Some(ref err) = r.error {
            (format!("ERR: {}", err), Color::Red)
        } else {
            ("SUCCESS".to_string(), Color::Green)
        };

        table.add_row(Row::from(vec![
            Cell::new(r.timestamp_unix.to_string()),
            Cell::new(&r.execution_id).fg(Color::White),
            Cell::new(&r.provider_name),
            Cell::new(&r.operation).fg(Color::Cyan),
            Cell::new(r.target_scope.to_string()),
            Cell::new(transition),
            recovery_cell,
            Cell::new(status_str).fg(status_color),
        ]));
    }

    println!("\nPersistent Router Policy Execution History:");
    println!("{table}\n");
}

pub fn render_router_inventory_table(
    items: &[crate::gateway::admin::NormalizedRouterInventoryItem],
) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Status").fg(Color::Cyan),
        Cell::new("Provider ID").fg(Color::Cyan),
        Cell::new("Display Name / Vendor").fg(Color::Cyan),
        Cell::new("Router Model / Identity").fg(Color::Cyan),
        Cell::new("Firmware").fg(Color::Cyan),
        Cell::new("Endpoint").fg(Color::Cyan),
        Cell::new("Last Contact").fg(Color::Cyan),
        Cell::new("Policies").fg(Color::Cyan),
        Cell::new("Devices").fg(Color::Cyan),
        Cell::new("Data Source").fg(Color::Cyan),
    ]);

    for item in items {
        let (status_str, status_color) = match &item.connection_state {
            crate::gateway::admin::ProviderConnectionState::Connected => {
                ("* CONNECTED", Color::Green)
            }
            crate::gateway::admin::ProviderConnectionState::AuthenticationRequired => {
                ("! AUTH REQUIRED", Color::Yellow)
            }
            crate::gateway::admin::ProviderConnectionState::Degraded(_) => {
                ("! DEGRADED", Color::Yellow)
            }
            crate::gateway::admin::ProviderConnectionState::Disconnected => {
                ("- DISCONNECTED", Color::DarkGrey)
            }
            crate::gateway::admin::ProviderConnectionState::Error(_) => ("x ERROR", Color::Red),
        };

        let identity_str = item
            .router_identity
            .as_ref()
            .map(|id| {
                format!(
                    "{} {}",
                    id.manufacturer.as_deref().unwrap_or(""),
                    id.model_name.as_deref().unwrap_or("Unknown")
                )
                .trim()
                .to_string()
            })
            .unwrap_or_else(|| "-".to_string());

        let fw_str = item.firmware_version.as_deref().unwrap_or("-");
        let endpoint_str = item.management_endpoint.as_deref().unwrap_or("-");
        let contact_str = item
            .last_contact_unix
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());

        let pol_str = item
            .active_policy_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());

        let dev_str = item
            .known_device_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());

        let (src_str, src_color) = match item.data_source {
            crate::gateway::admin::DataSource::Live => ("LIVE", Color::Green),
            crate::gateway::admin::DataSource::LocallyCached => ("CACHED", Color::Yellow),
            crate::gateway::admin::DataSource::StaticDescriptor => ("STATIC", Color::DarkGrey),
        };

        table.add_row(Row::from(vec![
            Cell::new(status_str).fg(status_color),
            Cell::new(&item.provider_id).fg(Color::White),
            Cell::new(format!("{} ({})", item.display_name, item.vendor)),
            Cell::new(identity_str),
            Cell::new(fw_str),
            Cell::new(endpoint_str),
            Cell::new(contact_str),
            Cell::new(pol_str),
            Cell::new(dev_str),
            Cell::new(src_str).fg(src_color),
        ]));
    }

    println!("\nNormalized Router Provider Inventory:");
    println!("{table}\n");
}

pub fn render_router_devices_table(devices: &[crate::gateway::admin::RouterDeviceEntry]) {
    if devices.is_empty() {
        println!("\nNo client devices reported by router.\n");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("IP Address").fg(Color::Cyan),
        Cell::new("MAC Address").fg(Color::Cyan),
        Cell::new("Hostname / Identifier").fg(Color::Cyan),
        Cell::new("Interface / Type").fg(Color::Cyan),
        Cell::new("Status").fg(Color::Cyan),
        Cell::new("Uptime").fg(Color::Cyan),
    ]);

    for d in devices {
        let ip_str =
            d.ip.map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string());
        let mac_str = d
            .mac
            .map(|mac| mac.to_string())
            .unwrap_or_else(|| "-".to_string());
        let host_str = d.hostname.as_deref().unwrap_or("-");
        let iface_str = d.interface_type.as_deref().unwrap_or("-");

        let (status_str, status_color) = match d.is_active {
            Some(true) => ("Active", Color::Green),
            Some(false) => ("Inactive", Color::DarkGrey),
            None => ("Unknown", Color::DarkGrey),
        };

        let uptime_str = if let Some(secs) = d.uptime_seconds {
            if secs >= 3600 {
                format!("{:.1}h", secs as f64 / 3600.0)
            } else {
                format!("{:.1}m", secs as f64 / 60.0)
            }
        } else {
            "-".to_string()
        };

        table.add_row(Row::from(vec![
            Cell::new(ip_str).fg(Color::White),
            Cell::new(mac_str),
            Cell::new(host_str),
            Cell::new(iface_str),
            Cell::new(status_str).fg(status_color),
            Cell::new(uptime_str),
        ]));
    }

    println!("\nRouter-Discovered Connected Devices / Clients (Read-Only):");
    println!("{table}\n");
}

pub fn render_router_diagnostics_report(report: &crate::gateway::admin::RouterDiagnosticReport) {
    use colored::Colorize;

    println!(
        "\n{}",
        "=======================================================".bright_cyan()
    );
    println!(
        "      {}  ",
        "ROUTER READ-ONLY DIAGNOSTIC REPORT".bright_yellow().bold()
    );
    println!(
        "{}",
        "=======================================================".bright_cyan()
    );
    println!(
        "  • Provider ID:         {}",
        report.provider_id.bright_white().bold()
    );
    println!(
        "  • Provider Name:       {}",
        report.provider_name.bright_cyan()
    );
    if let Some(ep) = &report.endpoint {
        println!("  • Management Endpoint: {}", ep.bright_white());
    }
    println!(
        "  • Diagnostic Time:     Unix timestamp {}",
        report.timestamp_unix
    );
    println!();

    // 1. Connection Status
    println!(
        "{}",
        "1. Transport & Connection Status:".bright_yellow().bold()
    );
    match &report.connection_status {
        crate::gateway::admin::DiagnosticResult::Supported(conn) => {
            let auth_str = if conn.is_authenticated {
                "YES".green().bold()
            } else {
                "NO (Authentication Required)".red().bold()
            };
            println!("  • Connected:           {}", "YES".green().bold());
            println!("  • Authenticated:       {}", auth_str);
            println!(
                "  • Protocol Transport:  {}",
                conn.transport_protocol.bright_cyan()
            );
            if let Some(lat) = conn.response_latency_ms {
                println!("  • Probe Latency:       {} ms", lat);
            }
        }
        crate::gateway::admin::DiagnosticResult::Failed(err) => {
            println!("  • Status:              {}", "FAILED".red().bold());
            println!("  • Diagnostic Error:    {}", err.red());
        }
        crate::gateway::admin::DiagnosticResult::Unsupported(reason) => {
            println!(
                "  • Status:              {} ({})",
                "UNSUPPORTED".yellow().bold(),
                reason
            );
        }
    }
    println!();

    // 2. Identity and Firmware
    println!(
        "{}",
        "2. Router Hardware & Firmware Identity:"
            .bright_yellow()
            .bold()
    );
    match &report.identity_and_version {
        crate::gateway::admin::DiagnosticResult::Supported(id) => {
            println!("  • IP Address:          {}", id.ip);
            println!(
                "  • Manufacturer:        {}",
                id.manufacturer.as_deref().unwrap_or("Unknown")
            );
            println!(
                "  • Model Name:          {}",
                id.model_name.as_deref().unwrap_or("Unknown")
            );
            println!(
                "  • Firmware Version:    {}",
                id.firmware_version.as_deref().unwrap_or("Unknown")
            );
            if let Some(rev) = &id.hardware_version {
                println!("  • Hardware Revision:   {}", rev);
            }
            if let Some(ser) = &id.serial_number {
                println!("  • Serial Number:       {}", ser);
            }
        }
        crate::gateway::admin::DiagnosticResult::Failed(err) => {
            println!("  • Status:              {}", "FAILED".red().bold());
            println!("  • Identity Error:      {}", err.red());
        }
        crate::gateway::admin::DiagnosticResult::Unsupported(reason) => {
            println!(
                "  • Status:              {} ({})",
                "UNSUPPORTED".yellow().bold(),
                reason
            );
        }
    }
    println!();

    // 3. Active Policy Inspection
    println!(
        "{}",
        "3. Active Firewall Rules Inspection (Read-Only):"
            .bright_yellow()
            .bold()
    );
    match &report.active_policies {
        crate::gateway::admin::DiagnosticResult::Supported(policies) => {
            println!(
                "  • Active Policies:     {} verified rule(s) on router",
                policies.len()
            );
            for p in policies {
                println!(
                    "    - Policy '{}' [{}] (Scope: {})",
                    p.policy_id.bright_yellow(),
                    p.lifecycle_state,
                    p.scope
                );
            }
        }
        crate::gateway::admin::DiagnosticResult::Failed(err) => {
            println!("  • Inspection Error:    {}", err.red());
        }
        crate::gateway::admin::DiagnosticResult::Unsupported(reason) => {
            println!(
                "  • Status:              {} ({})",
                "UNSUPPORTED".yellow().bold(),
                reason
            );
        }
    }
    println!();

    // 4. Connected Device Inventory
    println!(
        "{}",
        "4. Client Device Inventory (Read-Only):"
            .bright_yellow()
            .bold()
    );
    match &report.connected_devices {
        crate::gateway::admin::DiagnosticResult::Supported(devs) => {
            println!(
                "  • Discovered Clients:  {} client(s) reported by router",
                devs.len()
            );
        }
        crate::gateway::admin::DiagnosticResult::Unsupported(reason) => {
            println!(
                "  • Client Inventory:    {} ({})",
                "UNSUPPORTED".yellow().bold(),
                reason
            );
        }
        crate::gateway::admin::DiagnosticResult::Failed(err) => {
            println!(
                "  • Client Inventory:    {} ({})",
                "FAILED".red().bold(),
                err
            );
        }
    }
    println!();

    // 5. Capability Assessment
    println!(
        "{}",
        "5. Security & Enforcement Capabilities:"
            .bright_yellow()
            .bold()
    );
    match &report.capability_assessment {
        crate::gateway::admin::DiagnosticResult::Supported(caps) => {
            println!("  • Read-Only Discovery: {}", caps.read_only_discovery);
            println!("  • IPv4 Enforcement:    {}", caps.ipv4_policy_enforcement);
            println!("  • IPv6 Enforcement:    {}", caps.ipv6_policy_enforcement);
            println!(
                "  • Autonomous Recovery: {}",
                caps.timed_policy_auto_recovery
            );
        }
        crate::gateway::admin::DiagnosticResult::Unsupported(reason) => {
            println!(
                "  • Capabilities:        {} ({})",
                "UNSUPPORTED".yellow().bold(),
                reason
            );
        }
        crate::gateway::admin::DiagnosticResult::Failed(err) => {
            println!("  • Capabilities Error:  {}", err.red());
        }
    }
    println!();

    // 6. Recent Operational Errors
    println!(
        "{}",
        "6. Recent Operational Diagnostic Errors:"
            .bright_yellow()
            .bold()
    );
    if report.recent_errors.is_empty() {
        println!(
            "  • {}",
            "No recent errors recorded for this provider.".green()
        );
    } else {
        for err in &report.recent_errors {
            println!("  • {}", err.red());
        }
    }
    println!();
}
