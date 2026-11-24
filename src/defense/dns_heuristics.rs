use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DnsAnomalyAlert {
    HighEntropySubdomain {
        domain: String,
        label: String,
        entropy: f64,
    },
    ExcessiveLabelLength {
        domain: String,
        label: String,
        length: usize,
    },
}

/// Heuristic analyzer for identifying DNS tunneling, C2 communication, and covert data exfiltration.
pub struct DnsAnomalyEngine {
    entropy_threshold: f64,
    max_label_length: usize,
}

impl DnsAnomalyEngine {
    pub fn new(entropy_threshold: f64, max_label_length: usize) -> Self {
        Self {
            entropy_threshold,
            max_label_length,
        }
    }

    /// Computes Shannon entropy in bits for an input character sequence.
    pub fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freqs: HashMap<char, usize> = HashMap::new();
        for ch in s.chars() {
            *freqs.entry(ch).or_insert(0) += 1;
        }

        let total_chars = s.chars().count() as f64;
        let mut entropy = 0.0;
        for &count in freqs.values() {
            let p = count as f64 / total_chars;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Evaluates a domain name against length thresholds and Shannon entropy metrics.
    pub fn evaluate_domain(&self, domain: &str) -> Option<DnsAnomalyAlert> {
        let labels: Vec<&str> = domain.split('.').collect();

        // 1. Check for excessive single label length
        for &label in &labels {
            if label.len() > self.max_label_length {
                return Some(DnsAnomalyAlert::ExcessiveLabelLength {
                    domain: domain.to_string(),
                    label: label.to_string(),
                    length: label.len(),
                });
            }
        }

        // 2. Check for high-entropy obfuscation / encoded payloads in labels >= 15 chars
        for &label in &labels {
            if label.len() >= 15 {
                let ent = Self::calculate_entropy(label);
                if ent >= self.entropy_threshold {
                    return Some(DnsAnomalyAlert::HighEntropySubdomain {
                        domain: domain.to_string(),
                        label: label.to_string(),
                        entropy: ent,
                    });
                }
            }
        }

        None
    }
}
