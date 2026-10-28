use std::net::Ipv4Addr;

use crate::core::scope::ScopeManager;
use crate::types::MacAddress;

/// Classification of operational scope for target admission checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOperation {
    /// Local Layer 2 / Layer 3 destructive enforcement (ARP spoofing, traffic rate-limiting, packet fault simulation).
    /// Strictly requires a concrete network boundary (CIDR), non-gateway, non-controller, unicast IP and MAC,
    /// and rejecting subnet network and directed broadcast identifiers.
    LocalEnforcement,
    /// Router administrative policy (e.g. router-side internet pause or device firewall rule).
    /// Does not require Npcap injection, but strictly forbids targeting controller or gateway,
    /// and enforces unicast/valid IP targets.
    RouterPolicy,
}

/// Centralized validator for admitting network targets to enforcement operations.
///
/// Guarantees:
/// 1. Immutable Controller and Gateway exclusions (never targetable under any mode or configuration).
/// 2. Base IPv4 address and MAC syntax and unicast validity.
/// 3. Subnet network identifier and directed broadcast address rejection (RFC 3021 /31 and /32 preserved).
/// 4. Concrete boundary requirement for active local operations (permissive mode cannot target arbitrary out-of-LAN IPs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAdmissionValidator<'a> {
    pub controller_ip: Ipv4Addr,
    pub controller_mac: MacAddress,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddress,
    pub scope: &'a ScopeManager,
}

impl<'a> TargetAdmissionValidator<'a> {
    pub fn new(
        controller_ip: Ipv4Addr,
        controller_mac: MacAddress,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddress,
        scope: &'a ScopeManager,
    ) -> Self {
        Self {
            controller_ip,
            controller_mac,
            gateway_ip,
            gateway_mac,
            scope,
        }
    }

    /// Validates an IP and optional MAC address for the given admission operation.
    pub fn validate_target(
        &self,
        ip: &Ipv4Addr,
        mac: Option<&MacAddress>,
        op: AdmissionOperation,
    ) -> Result<(), String> {
        // 1. Mandatory Controller & Gateway Exclusions (Immutable)
        if *ip == self.controller_ip {
            return Err(format!(
                "Local controller IP {} cannot be an enforcement target",
                ip
            ));
        }
        if *ip == self.gateway_ip {
            return Err(format!(
                "Default gateway IP {} cannot be an enforcement target",
                ip
            ));
        }

        if let Some(m) = mac {
            if !m.is_zero() {
                if !self.controller_mac.is_zero() && *m == self.controller_mac {
                    return Err(format!(
                        "Local controller MAC {} cannot be an enforcement target",
                        m
                    ));
                }
                if !self.gateway_mac.is_zero() && *m == self.gateway_mac {
                    return Err(format!(
                        "Default gateway MAC {} cannot be an enforcement target",
                        m
                    ));
                }
            }
        }

        // 2. Base Scope validation (unspecified, loopback, broadcast, multicast,
        // MAC validity, explicit exclusions, subnet network ID, directed broadcast)
        self.scope.validate_target(ip, mac)?;

        // 3. Concrete boundary enforcement:
        // In strict mode (strict_mode == true), destructive local operations (block, limit, simulate)
        // require the target IP to be contained within an explicitly authorized CIDR boundary.
        // In permissive mode (strict_mode == false), all private LAN addresses (RFC 1918, CGNAT, link-local)
        // and any explicitly allowed CIDRs are admitted; arbitrary public Internet IPs (e.g. 8.8.8.8) are rejected.
        if matches!(op, AdmissionOperation::LocalEnforcement) {
            if self.scope.allowed_cidrs.is_empty() {
                return Err(
                    "Target rejected: Active local enforcement requires an explicit authorized CIDR or interface subnet boundary, but none are defined."
                        .into(),
                );
            }
            if self.scope.strict_mode {
                if !self.scope.allowed_cidrs.iter().any(|c| c.contains(ip)) {
                    return Err(format!(
                        "Target IP {} is outside authorized network boundary CIDRs for active local enforcement.",
                        ip
                    ));
                }
            } else {
                let is_private = ip.is_private()
                    || ip.is_link_local()
                    || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64); // RFC 6598 100.64.0.0/10

                let in_allowed = self.scope.allowed_cidrs.iter().any(|c| c.contains(ip));

                if !is_private && !in_allowed {
                    return Err(format!(
                        "Target IP {} is outside authorized network boundary CIDRs for active local enforcement.",
                        ip
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scope::Ipv4Cidr;

    #[test]
    fn test_admission_mandatory_controller_and_gateway_exclusions() {
        let mut scope = ScopeManager::new();
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        scope.add_cidr_direct(cidr);

        let c_ip = Ipv4Addr::new(192, 168, 1, 100);
        let c_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();
        let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
        let gw_mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();

        let validator = TargetAdmissionValidator::new(c_ip, c_mac, gw_ip, gw_mac, &scope);

        // Controller IP rejected
        let res_c_ip = validator.validate_target(&c_ip, None, AdmissionOperation::LocalEnforcement);
        assert!(res_c_ip.is_err());
        assert!(res_c_ip.unwrap_err().contains("Local controller IP"));

        // Gateway IP rejected
        let res_gw_ip =
            validator.validate_target(&gw_ip, None, AdmissionOperation::LocalEnforcement);
        assert!(res_gw_ip.is_err());
        assert!(res_gw_ip.unwrap_err().contains("Default gateway IP"));

        // Controller MAC rejected
        let other_ip = Ipv4Addr::new(192, 168, 1, 50);
        let res_c_mac = validator.validate_target(
            &other_ip,
            Some(&c_mac),
            AdmissionOperation::LocalEnforcement,
        );
        assert!(res_c_mac.is_err());
        assert!(res_c_mac.unwrap_err().contains("Local controller MAC"));

        // Gateway MAC rejected
        let res_gw_mac = validator.validate_target(
            &other_ip,
            Some(&gw_mac),
            AdmissionOperation::LocalEnforcement,
        );
        assert!(res_gw_mac.is_err());
        assert!(res_gw_mac.unwrap_err().contains("Default gateway MAC"));

        // Valid third party host accepted
        let target_mac: MacAddress = "12:34:56:78:9A:BC".parse().unwrap();
        let ok_res = validator.validate_target(
            &other_ip,
            Some(&target_mac),
            AdmissionOperation::LocalEnforcement,
        );
        assert!(ok_res.is_ok());
    }

    #[test]
    fn test_admission_concrete_boundary_required_even_in_permissive_mode() {
        let mut scope = ScopeManager::new();
        // strict_mode is FALSE by default
        assert!(!scope.strict_mode);

        let c_ip = Ipv4Addr::new(192, 168, 1, 100);
        let c_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();
        let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
        let gw_mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();

        let validator = TargetAdmissionValidator::new(c_ip, c_mac, gw_ip, gw_mac, &scope);

        // When allowed_cidrs is empty, local enforcement must reject any target
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);
        let res_empty =
            validator.validate_target(&target_ip, None, AdmissionOperation::LocalEnforcement);
        assert!(res_empty.is_err());
        assert!(res_empty
            .unwrap_err()
            .contains("requires an explicit authorized CIDR or interface subnet boundary"));

        // Add LAN boundary
        scope.add_cidr_direct(Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
        let validator2 = TargetAdmissionValidator::new(c_ip, c_mac, gw_ip, gw_mac, &scope);

        // Out-of-boundary IP still rejected even with strict_mode = false
        let res_out =
            validator2.validate_target(&target_ip, None, AdmissionOperation::LocalEnforcement);
        assert!(res_out.is_err());
        assert!(res_out
            .unwrap_err()
            .contains("outside authorized network boundary CIDRs"));

        // In-boundary IP accepted
        let in_boundary_ip = Ipv4Addr::new(192, 168, 1, 42);
        assert!(validator2
            .validate_target(&in_boundary_ip, None, AdmissionOperation::LocalEnforcement)
            .is_ok());

        // In permissive mode (strict_mode == false), private LAN targets across other subnets are admitted
        let cross_subnet_private = Ipv4Addr::new(192, 168, 36, 84);
        assert!(validator2
            .validate_target(&cross_subnet_private, None, AdmissionOperation::LocalEnforcement)
            .is_ok());
        let class_a_private = Ipv4Addr::new(10, 76, 113, 26);
        assert!(validator2
            .validate_target(&class_a_private, None, AdmissionOperation::LocalEnforcement)
            .is_ok());
    }
}
