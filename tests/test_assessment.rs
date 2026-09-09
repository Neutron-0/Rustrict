use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use rustrict::cli::export::{export_json, export_markdown, export_sarif};
use rustrict::core::assessment::{AuditFinding, AuditSeverity, PortStatus, ServiceEntry};
use rustrict::core::scope::{Ipv4Cidr, ScopeManager};
use rustrict::limiter::FaultProfile;
use rustrict::probes::parse_ports_arg;
use rustrict::types::MacAddress;

#[test]
fn test_cidr_containment_and_normalization() {
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
    // Network must be normalized to 192.168.1.0
    assert_eq!(cidr.network, Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(cidr.prefix, 24);

    assert!(cidr.contains(&Ipv4Addr::new(192, 168, 1, 1)));
    assert!(cidr.contains(&Ipv4Addr::new(192, 168, 1, 254)));
    assert!(!cidr.contains(&Ipv4Addr::new(192, 168, 2, 1)));
    assert!(!cidr.contains(&Ipv4Addr::new(10, 0, 0, 1)));

    // Test CIDR parsing from string
    let parsed: Ipv4Cidr = "10.10.0.0/16".parse().unwrap();
    assert_eq!(parsed.prefix, 16);
    assert!(parsed.contains(&Ipv4Addr::new(10, 10, 42, 1)));
    assert!(!parsed.contains(&Ipv4Addr::new(10, 11, 0, 1)));

    // Single host CIDR /32
    let host_cidr: Ipv4Cidr = "192.168.1.50".parse().unwrap();
    assert_eq!(host_cidr.prefix, 32);
    assert!(host_cidr.contains(&Ipv4Addr::new(192, 168, 1, 50)));
    assert!(!host_cidr.contains(&Ipv4Addr::new(192, 168, 1, 51)));
}

#[test]
fn test_scope_manager_boundaries_and_exclusions() {
    let mut scope = ScopeManager::new();
    let subnet = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
    scope.add_cidr_direct(subnet);

    let allowed_ip = Ipv4Addr::new(192, 168, 1, 10);
    let out_of_scope_ip = Ipv4Addr::new(10, 0, 0, 5);
    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // When strict mode is false, out of scope IPs are not blocked by default
    assert!(scope.validate_target(&allowed_ip, Some(&mac)).is_ok());
    assert!(scope.validate_target(&out_of_scope_ip, Some(&mac)).is_ok());

    // Enable strict mode
    scope.set_strict(true);
    assert!(scope.validate_target(&allowed_ip, Some(&mac)).is_ok());
    let err = scope.validate_target(&out_of_scope_ip, Some(&mac));
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("out of authorized scope"));

    // Exclude specific IP
    scope.exclude_ip(allowed_ip);
    let err = scope.validate_target(&allowed_ip, Some(&mac));
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("explicitly excluded"));

    // Exclude MAC
    let excluded_mac = MacAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    scope.exclude_mac(excluded_mac);
    let fresh_ip = Ipv4Addr::new(192, 168, 1, 20);
    let err = scope.validate_target(&fresh_ip, Some(&excluded_mac));
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("MAC"));
}

#[test]
fn test_port_argument_parsing() {
    // Single port
    let ports = parse_ports_arg("80").unwrap();
    assert_eq!(ports, vec![80]);

    // Comma separated list
    let ports = parse_ports_arg("80, 443, 8080").unwrap();
    assert_eq!(ports, vec![80, 443, 8080]);

    // Range
    let ports = parse_ports_arg("8000-8003").unwrap();
    assert_eq!(ports, vec![8000, 8001, 8002, 8003]);

    // Mixed with duplicates
    let ports = parse_ports_arg("80, 8000-8002, 443, 80").unwrap();
    assert_eq!(ports, vec![80, 8000, 8001, 8002, 443]);

    // Error handling
    assert!(parse_ports_arg("").is_err());
    assert!(parse_ports_arg("abc").is_err());
    assert!(parse_ports_arg("9000-8000").is_err()); // Inverted range
    assert!(parse_ports_arg("1-70000").is_err()); // Port out of u16 range
}

#[test]
fn test_fault_profile_simulation_metrics() {
    let profile = FaultProfile::new(0, 50, 0);
    assert!(profile.is_active());
    assert!(!profile.should_drop());
    assert_eq!(profile.compute_delay().as_millis(), 50);

    let drop_profile = FaultProfile::new(100, 0, 0);
    assert!(drop_profile.is_active());
    assert!(drop_profile.should_drop());

    let jitter_profile = FaultProfile::new(0, 100, 20);
    let delay = jitter_profile.compute_delay().as_millis();
    assert!((80..=120).contains(&delay));
}


#[test]
fn test_report_export_markdown_json_sarif() {
    let mut scope = ScopeManager::new();
    scope.add_cidr("192.168.1.0/24").unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let mut services = HashMap::new();
    services.insert(
        target_ip,
        vec![
            ServiceEntry {
                port: 443,
                transport: "tcp".to_string(),
                service_name: "https".to_string(),
                banner: Some("Server: nginx/1.24.0".to_string()),
                status: PortStatus::Open,
            },
            ServiceEntry {
                port: 445,
                transport: "tcp".to_string(),
                service_name: "microsoft-ds".to_string(),
                banner: None,
                status: PortStatus::Open,
            },
        ],
    );

    let findings = vec![
        AuditFinding::new(
            "SMB-SIGNING-NOT-REQUIRED",
            "SMB Message Signing Not Enforced",
            target_ip,
            Some(445),
            AuditSeverity::High,
            "Target supports SMBv2/SMBv3 but does not mandate message signing.",
            "Configure group policy or registry to require SMB packet signing.",
        ),
        AuditFinding::new(
            "TLS-LEGACY-V10",
            "Legacy Insecure TLS 1.0 Protocol Supported",
            target_ip,
            Some(443),
            AuditSeverity::Medium,
            "Target accepted a TLS 1.0 ClientHello.",
            "Disable TLS 1.0 and TLS 1.1 on the server.",
        ),
    ];

    // Markdown Verification
    let md = export_markdown(&scope, &services, &findings);
    assert!(md.contains("# Rustrict Active Posture & Assessment Report"));
    assert!(md.contains("Hosts with Open Services | 1"));
    assert!(md.contains("Total Discovered Services | 2"));
    assert!(md.contains("Total Security Findings | 2"));
    assert!(md.contains("SMB-SIGNING-NOT-REQUIRED"));
    assert!(md.contains("TLS-LEGACY-V10"));
    assert!(md.contains("Server: nginx/1.24.0"));

    // JSON Verification
    let json_str = export_json(&scope, &services, &findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["tool"], "Rustrict");
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 2);
    assert_eq!(parsed["services"]["192.168.1.100"].as_array().unwrap().len(), 2);

    // SARIF Verification
    let sarif_str = export_sarif(&findings).unwrap();
    let sarif_json: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    let runs = &sarif_json["runs"][0];
    assert_eq!(runs["tool"]["driver"]["name"], "Rustrict");
    assert_eq!(runs["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
    assert_eq!(runs["results"].as_array().unwrap().len(), 2);


    let result1 = &runs["results"][0];
    assert_eq!(result1["ruleId"], "SMB-SIGNING-NOT-REQUIRED");
    assert_eq!(result1["level"], "error"); // High -> error
}
