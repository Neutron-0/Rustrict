use rustrict::defense::dns_heuristics::{DnsAnomalyAlert, DnsAnomalyEngine};

#[test]
fn test_shannon_entropy_and_dns_tunneling_detection() {
    let engine = DnsAnomalyEngine::new(3.8, 35); // Entropy threshold 3.8 bits, max label length 35

    // 1. Normal benign domains
    assert_eq!(engine.evaluate_domain("google.com"), None);
    assert_eq!(engine.evaluate_domain("api.github.com"), None);
    assert_eq!(engine.evaluate_domain("cdn.cdnjs.cloudflare.com"), None);

    // 2. High-entropy base64/hex tunneling domain -> Alert!
    let tunneling_domain = "a8f7e3c9b1d4e2f6a0c5b3d1e4f2a7c9.tunnel.attacker-c2.net";
    let alert = engine.evaluate_domain(tunneling_domain);
    assert!(alert.is_some());
    match alert.unwrap() {
        DnsAnomalyAlert::HighEntropySubdomain { domain, entropy, label } => {
            assert_eq!(domain, tunneling_domain);
            assert_eq!(label, "a8f7e3c9b1d4e2f6a0c5b3d1e4f2a7c9");
            assert!(entropy >= 3.8);
        }
        other => panic!("Expected HighEntropySubdomain, got {:?}", other),
    }

    // 3. Excessively long label anomaly
    let long_label_domain = "this-is-an-unusually-long-single-subdomain-label-exceeding-threshold.example.com";
    let alert_long = engine.evaluate_domain(long_label_domain);
    assert!(alert_long.is_some());
    match alert_long.unwrap() {
        DnsAnomalyAlert::ExcessiveLabelLength { domain, length, .. } => {
            assert_eq!(domain, long_label_domain);
            assert!(length > 35);
        }
        other => panic!("Expected ExcessiveLabelLength, got {:?}", other),
    }
}
