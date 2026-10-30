use colored::*;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::cli::table::{
    render_findings_table, render_hosts_table, render_router_capabilities_table,
    render_router_devices_table, render_router_diagnostics_report, render_router_history_table,
    render_router_inventory_table, render_router_plan_preview, render_router_policies_table,
    render_router_policy_detail, render_router_providers_table,
    render_router_unified_policies_table, render_scope_table, render_services_table,
};
use crate::core::admission::{AdmissionOperation, TargetAdmissionValidator};
use crate::core::assessment::{AuditFinding, ServiceEntry};
use crate::core::scope::{Ipv4Cidr, ScopeManager};
use crate::gateway::admin::{
    find_ssh_client, AvmAdminProvider, HttpAvmTransport, HttpUnifiTransport,
    HttpsMikroTikTransport, MikroTikAdminProvider, MockRouterAdminProvider, OpenWrtAdminProvider,
    OperationPlanRequest, PolicyDuration, PolicyExecutionEngine, PolicyPersistence, PolicyScope,
    RouterAdminProvider, RouterCredentials, RouterRegistry, SshConfig, SshOpenWrtTransport,
    UnifiAdminProvider,
};
use crate::limiter::{FaultProfile, TrafficLimiter};
use crate::scanner::SubnetScanner;
use crate::spoofer::ArpSpoofer;
use crate::types::{BitRate, Direction, Host, HostStatus, MacAddress, NetworkInterface};

pub struct RustrictCli {
    #[allow(dead_code)]
    iface: NetworkInterface,
    scanner: SubnetScanner,
    spoofer: ArpSpoofer,
    limiter: TrafficLimiter,
    sniffer: crate::resolver::passive::PassiveIdentitySniffer,
    hosts: Vec<Host>,
    persistent_state: crate::state::PersistentState,
    scope: ScopeManager,
    services: HashMap<Ipv4Addr, Vec<ServiceEntry>>,
    findings: Vec<AuditFinding>,
    admin_provider: Arc<dyn RouterAdminProvider>,
    router_registry: Arc<RouterRegistry>,
    policy_engine: Arc<PolicyExecutionEngine>,
    simulated_inputs: Vec<String>,
    pub is_router_lab: bool,
}

/// Reads password from console with echo disabled to prevent credential leaking
fn read_masked_password() -> io::Result<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
        };
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if !handle.is_null()
                && handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
                && GetConsoleMode(handle, &mut mode) != 0
            {
                let prev_mode = mode;
                let no_echo = mode & !ENABLE_ECHO_INPUT;
                SetConsoleMode(handle, no_echo);

                let mut input = String::new();
                let res = io::stdin().read_line(&mut input);

                SetConsoleMode(handle, prev_mode);
                println!(); // Print newline since Enter wasn't echoed

                return res.map(|_| input.trim().trim_start_matches('\u{feff}').to_string());
            }
        }
    }

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().trim_start_matches('\u{feff}').to_string())
}

impl RustrictCli {
    pub fn new(iface: NetworkInterface) -> Self {
        let scanner = SubnetScanner::new(iface.ip, iface.netmask, iface.gateway);
        let spoofer = ArpSpoofer::new(
            &iface.device_path,
            iface.mac,
            iface.gateway,
            iface.gateway_mac,
        );
        let limiter = TrafficLimiter::new();
        let sniffer = crate::resolver::passive::PassiveIdentitySniffer::new(&iface.device_path);
        let persistent_state = crate::state::PersistentState::load();

        let mut scope = if let Some(mut saved_scope) = persistent_state.scope.clone() {
            saved_scope.sanitize();
            saved_scope
        } else {
            ScopeManager::default()
        };
        // Default to permissive LAN operations
        scope.set_strict(false);

        // Always ensure the current active interface's subnet is present in the operational scope
        let prefix = u32::from(iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
            if !scope.allowed_cidrs.contains(&local_cidr) {
                scope.add_cidr_direct(local_cidr);
            }
        }

        let mut hosts = Vec::new();

        if !persistent_state.blocked_hosts.is_empty() {
            println!(
                "{} Restoring {} persistent blocked device(s) from state...",
                "[INFO]".cyan().bold(),
                persistent_state.blocked_hosts.len()
            );

            struct LiveEnforcementSink<'a> {
                spoofer: &'a ArpSpoofer,
                limiter: &'a TrafficLimiter,
            }

            impl<'a> crate::core::PersistentBlockActivator for LiveEnforcementSink<'a> {
                fn is_injection_ready(&self) -> bool {
                    self.spoofer.has_sender()
                }

                fn activate(&mut self, host: &Host, dir: Direction) -> Result<(), String> {
                    self.spoofer.add(host.clone())?;
                    self.limiter.block(host.ip, dir);
                    Ok(())
                }
            }

            let mut sink = LiveEnforcementSink {
                spoofer: &spoofer,
                limiter: &limiter,
            };

            let net_params = crate::core::RestorationNetworkParams {
                iface_ip: iface.ip,
                iface_mac: iface.mac,
                iface_name: &iface.name,
                gateway_ip: iface.gateway,
                gateway_mac: iface.gateway_mac,
            };

            let report = crate::core::restore_persistent_blocks_with(
                &persistent_state.blocked_hosts,
                |ip| persistent_state.get_direction(ip),
                &net_params,
                &scope,
                &crate::core::SystemForwardingEnabler,
                &mut sink,
            );

            if !report.activated_targets.is_empty() {
                println!(
                    "{} Restored and activated {} persistent block(s)",
                    "OK".green().bold(),
                    report.activated_targets.len()
                );
            }

            if !report.inactive_targets.is_empty() {
                println!(
                    "{} Restored {} persistent blocked device(s) as INACTIVE (enforcement not activated): {}",
                    "[WARN]".yellow().bold(),
                    report.inactive_targets.len(),
                    report
                        .failure_reason
                        .as_deref()
                        .unwrap_or("Preconditions not met")
                );
            }

            for (skipped_ip, reason) in &report.skipped_targets {
                println!(
                    "{} Skipping restored persistent record {}: {}",
                    "[WARN]".yellow().bold(),
                    skipped_ip,
                    reason
                );
            }

            hosts = report.restored_hosts;
        }

        let spoofer_clone = spoofer.clone();
        let limiter_clone = limiter.clone();
        crate::platform::register_shutdown_handler(move || {
            limiter_clone.stop();
            spoofer_clone.stop();
        });

        let router_registry = Arc::new(RouterRegistry::new(iface.gateway));
        router_registry.set_controller_ip(iface.ip);
        let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
        let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;

        println!(
            "{} Scope Mode: {}  |  Block Mode: {}",
            "[CONFIG]".bright_cyan().bold(),
            if scope.strict_mode {
                "STRICT (Only explicitly authorized CIDRs)".yellow().bold()
            } else {
                "PERMISSIVE (All private LANs permitted)"
                    .bright_green()
                    .bold()
            },
            match spoofer.mode() {
                crate::spoofer::SpooferMode::Blackhole =>
                    "L2 Blackhole (02:bf:00:00:00:01)".green(),
                crate::spoofer::SpooferMode::Mitm => "MITM WinDivert Kernel Drop".cyan(),
            }
        );

        Self {
            iface,
            scanner,
            spoofer,
            limiter,
            sniffer,
            hosts,
            persistent_state,
            scope,
            services: HashMap::new(),
            findings: Vec::new(),
            admin_provider,
            router_registry,
            policy_engine,
            simulated_inputs: Vec::new(),
            is_router_lab: false,
        }
    }

    /// Creates a decoupled offline session without live network packet injection or adapter binding.
    pub fn new_offline(iface: NetworkInterface) -> Self {
        let scanner = SubnetScanner::new(iface.ip, iface.netmask, iface.gateway);
        let spoofer = ArpSpoofer::new_inactive(iface.mac, iface.gateway, iface.gateway_mac);
        let limiter = TrafficLimiter::new();
        let sniffer = crate::resolver::passive::PassiveIdentitySniffer::new_inactive();
        let persistent_state = crate::state::PersistentState::load();

        let mut scope = if let Some(mut saved_scope) = persistent_state.scope.clone() {
            saved_scope.sanitize();
            saved_scope
        } else {
            ScopeManager::default()
        };
        // Default to permissive LAN operations
        scope.set_strict(false);

        let prefix = u32::from(iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
            if !scope.allowed_cidrs.contains(&local_cidr) {
                scope.add_cidr_direct(local_cidr);
            }
        }

        let mut hosts = Vec::new();
        if !persistent_state.blocked_hosts.is_empty() {
            for (idx, b) in persistent_state.blocked_hosts.iter().enumerate() {
                let mac = b.mac.parse().unwrap_or(MacAddress::ZERO);
                let dir = persistent_state.get_direction(&b.ip);
                let mut host = Host::with_source(
                    idx,
                    b.ip,
                    mac,
                    b.name.clone(),
                    crate::types::NameSource::Manual,
                    "Persisted Device".into(),
                );
                host.status = HostStatus::PersistedInactive(dir);
                host.persistent_block = true;
                hosts.push(host);
            }
        }

        let router_registry = Arc::new(RouterRegistry::new(iface.gateway));
        router_registry.set_controller_ip(iface.ip);
        let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
        let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;

        Self {
            iface,
            scanner,
            spoofer,
            limiter,
            sniffer,
            hosts,
            persistent_state,
            scope,
            services: HashMap::new(),
            findings: Vec::new(),
            admin_provider,
            router_registry,
            policy_engine,
            simulated_inputs: Vec::new(),
            is_router_lab: true,
        }
    }

    /// Creates a read-only router lab environment.
    /// In this mode, no raw Layer 2 packet injection sender is initialized,
    /// persistent blocks are loaded as inactive inventory without activation,
    /// OS forwarding is never touched, and local destructive commands (block, limit, simulate)
    /// are strictly disabled.
    pub fn new_router_lab(iface: NetworkInterface) -> Self {
        let scanner = SubnetScanner::new(iface.ip, iface.netmask, iface.gateway);
        let spoofer = ArpSpoofer::new_inactive(iface.mac, iface.gateway, iface.gateway_mac);
        let limiter = TrafficLimiter::new();
        let sniffer = crate::resolver::passive::PassiveIdentitySniffer::new_inactive();
        let persistent_state = crate::state::PersistentState::load();

        let mut scope = if let Some(mut saved_scope) = persistent_state.scope.clone() {
            saved_scope.sanitize();
            saved_scope
        } else {
            ScopeManager::default()
        };
        // Default to permissive LAN operations
        scope.set_strict(false);

        // Always ensure the current active interface's subnet is present in the operational scope
        let prefix = u32::from(iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
            if !scope.allowed_cidrs.contains(&local_cidr) {
                scope.add_cidr_direct(local_cidr);
            }
        }

        let mut hosts = Vec::new();
        if !persistent_state.blocked_hosts.is_empty() {
            println!(
                "{} Router-lab mode: Loading {} persistent blocked device(s) as INACTIVE (local enforcement disabled)...",
                "[INFO]".cyan().bold(),
                persistent_state.blocked_hosts.len()
            );
            for (idx, b) in persistent_state.blocked_hosts.iter().enumerate() {
                let mac = b.mac.parse().unwrap_or(MacAddress::ZERO);
                let dir = persistent_state.get_direction(&b.ip);
                let mut host = Host::with_source(
                    idx,
                    b.ip,
                    mac,
                    b.name.clone(),
                    crate::types::NameSource::Manual,
                    "Persisted Device".into(),
                );
                host.status = HostStatus::PersistedInactive(dir);
                host.persistent_block = true;
                hosts.push(host);
            }
        }

        let router_registry = Arc::new(RouterRegistry::new(iface.gateway));
        router_registry.set_controller_ip(iface.ip);
        let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
        let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;

        println!(
            "{} Scope Mode: {}  |  Block Mode: {}",
            "[CONFIG]".bright_cyan().bold(),
            if scope.strict_mode {
                "STRICT (Only explicitly authorized CIDRs)".yellow().bold()
            } else {
                "PERMISSIVE (All private LANs permitted)"
                    .bright_green()
                    .bold()
            },
            match spoofer.mode() {
                crate::spoofer::SpooferMode::Blackhole =>
                    "L2 Blackhole (02:bf:00:00:00:01)".green(),
                crate::spoofer::SpooferMode::Mitm => "MITM WinDivert Kernel Drop".cyan(),
            }
        );

        Self {
            iface,
            scanner,
            spoofer,
            limiter,
            sniffer,
            hosts,
            persistent_state,
            scope,
            services: HashMap::new(),
            findings: Vec::new(),
            admin_provider,
            router_registry,
            policy_engine,
            simulated_inputs: Vec::new(),
            is_router_lab: true,
        }
    }

    /// Bootstraps a router lab CLI instance using an injected InterfaceResolver.
    /// This guarantees that interface resolution performs zero active network probes (no SendARP, no ICMP pings).
    pub fn bootstrap_router_lab<I: crate::platform::InterfaceResolver>(
        resolver: &I,
    ) -> Result<Self, String> {
        let iface = resolver.resolve_interface()?;
        Ok(Self::new_router_lab(iface))
    }

    pub fn new_for_testing() -> Self {
        let iface = NetworkInterface {
            name: "test_iface".into(),
            description: "Loopback Test Interface".into(),
            ip: Ipv4Addr::new(127, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(127, 0, 0, 1),
            gateway_mac: MacAddress::ZERO,
            mac: MacAddress::ZERO,
            device_path: "\\Device\\NPF_Loopback".into(),
        };
        let scanner = SubnetScanner::new(iface.ip, iface.netmask, iface.gateway);
        let spoofer = ArpSpoofer::new_inactive(iface.mac, iface.gateway, iface.gateway_mac);
        let limiter = TrafficLimiter::new();
        let sniffer = crate::resolver::passive::PassiveIdentitySniffer::new_inactive();
        let persistent_state = crate::state::PersistentState::default();
        let mut scope = ScopeManager::default();
        let prefix = u32::from(iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
            scope.add_cidr_direct(local_cidr);
        }
        let router_registry = Arc::new(RouterRegistry::new(iface.gateway));
        router_registry.set_controller_ip(iface.ip);
        let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
        let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;

        println!(
            "{} Scope Mode: {}  |  Block Mode: {}",
            "[CONFIG]".bright_cyan().bold(),
            if scope.strict_mode {
                "STRICT (Only explicitly authorized CIDRs)".yellow().bold()
            } else {
                "PERMISSIVE (All private LANs permitted)"
                    .bright_green()
                    .bold()
            },
            match spoofer.mode() {
                crate::spoofer::SpooferMode::Blackhole =>
                    "L2 Blackhole (02:bf:00:00:00:01)".green(),
                crate::spoofer::SpooferMode::Mitm => "MITM WinDivert Kernel Drop".cyan(),
            }
        );

        Self {
            iface,
            scanner,
            spoofer,
            limiter,
            sniffer,
            hosts: Vec::new(),
            persistent_state,
            scope,
            services: HashMap::new(),
            findings: Vec::new(),
            admin_provider,
            router_registry,
            policy_engine,
            simulated_inputs: Vec::new(),
            is_router_lab: false,
        }
    }

    /// Creates a test CLI instance with a dummy L2 packet injection sender.
    pub fn new_with_dummy_injection_for_testing() -> Self {
        let mut cli = Self::new_for_testing();
        cli.spoofer = ArpSpoofer::new_with_dummy_sender_for_testing(
            cli.iface.mac,
            cli.iface.gateway,
            cli.iface.gateway_mac,
        );
        cli
    }

    pub fn admission_validator(&self) -> TargetAdmissionValidator<'_> {
        TargetAdmissionValidator::new(
            self.iface.ip,
            self.iface.mac,
            self.iface.gateway,
            self.iface.gateway_mac,
            &self.scope,
        )
    }

    pub fn with_simulated_inputs(mut self, inputs: Vec<String>) -> Self {
        self.simulated_inputs = inputs;
        self
    }

    pub fn add_simulated_input(&mut self, input: impl Into<String>) {
        self.simulated_inputs.push(input.into());
    }

    pub fn read_confirmation_input(&mut self) -> io::Result<String> {
        if !self.simulated_inputs.is_empty() {
            Ok(self.simulated_inputs.remove(0))
        } else {
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Ok(input)
        }
    }

    pub fn router_registry(&self) -> &Arc<RouterRegistry> {
        &self.router_registry
    }

    pub fn policy_engine(&self) -> &Arc<PolicyExecutionEngine> {
        &self.policy_engine
    }

    pub fn iface(&self) -> &NetworkInterface {
        &self.iface
    }

    pub fn is_router_lab(&self) -> bool {
        self.is_router_lab
    }

    pub fn scope(&self) -> &ScopeManager {
        &self.scope
    }

    pub fn spoofer(&self) -> &ArpSpoofer {
        &self.spoofer
    }

    pub fn set_spoofer(&mut self, spoofer: ArpSpoofer) {
        self.spoofer = spoofer;
    }

    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }

    pub fn hosts_mut(&mut self) -> &mut Vec<Host> {
        &mut self.hosts
    }

    pub fn set_hosts(&mut self, hosts: Vec<Host>) {
        self.hosts = hosts;
    }

    pub fn add_host(&mut self, host: Host) {
        self.hosts.push(host);
    }

    pub fn with_admin_provider(mut self, provider: Arc<dyn RouterAdminProvider>) -> Self {
        let _ = self
            .router_registry
            .connect("mock", provider.clone(), "internal://in-memory");
        self.admin_provider = self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
        self
    }

    pub fn admin_provider(&self) -> &Arc<dyn RouterAdminProvider> {
        &self.admin_provider
    }

    pub fn shutdown(&mut self) {
        self.limiter.stop();
        self.spoofer.stop();
        self.sniffer.stop();
    }

    /// Evaluates a command against the strict default-deny router-lab policy.
    /// Returns Ok(()) if allowed, or Err(reason) if denied.
    pub fn is_command_allowed_in_router_lab(&self, args: &[&str]) -> Result<(), String> {
        if !self.is_router_lab {
            return Ok(());
        }

        if args.is_empty() {
            return Ok(());
        }

        let cmd = args[0].to_lowercase();
        match cmd.as_str() {
            "help" | "?" | "clear" | "cls" | "quit" | "exit" | "upgrade" | "update" | "blockmode" | "spoofer" => Ok(()),
            "hosts" | "devices" | "targets" | "list" | "ls" => Ok(()),
            "status" => Ok(()),
            "state" => Ok(()),
            "nic" | "adapter" => Ok(()),
            "router" => {
                if args.len() < 2 || args[1].eq_ignore_ascii_case("help") {
                    return Ok(());
                }
                let sub = args[1].to_lowercase();
                match sub.as_str() {
                    "providers"
                    | "capabilities"
                    | "caps"
                    | "status"
                    | "diagnostics"
                    | "diag"
                    | "devices"
                    | "clients"
                    | "inventory"
                    | "policies"
                    | "policy"
                    | "history"
                    | "records"
                    | "export-evidence"
                    | "validate-evidence"
                    | "validate"
                    | "disconnect" => Ok(()),
                    "export" => Ok(()),
                    "preview" => Ok(()),
                    "connect" => {
                        // In router-lab mode, connecting to real providers is permitted,
                        // but mock router provider is strictly rejected to prevent
                        // recording simulated results as physical validation.
                        if args.len() > 2 && args[2..].iter().any(|a| a.eq_ignore_ascii_case("mock")) {
                            Err("Mock router provider is prohibited in router-lab mode. Connect to a real supported provider for hardware validation.".to_string())
                        } else {
                            Ok(())
                        }
                    }
                    "pause" => Err("Command 'router pause' is blocked in router-lab mode: policy enforcement mutations are strictly prohibited.".to_string()),
                    "resume" => Err("Command 'router resume' is blocked in router-lab mode: policy revocation mutations are strictly prohibited.".to_string()),
                    "adjust" => Err("Command 'router adjust' is blocked in router-lab mode: policy adjustment mutations are strictly prohibited.".to_string()),
                    "refresh" | "reconcile" => Err("Command 'router refresh' is blocked in router-lab mode: policy store reconciliation is prohibited.".to_string()),
                    other => Err(format!(
                        "Subcommand 'router {}' is not allowed in router-lab mode (default-deny policy).",
                        other
                    )),
                }
            }
            "scan" => Err("Command 'scan' is blocked in router-lab mode: active network scanning is strictly prohibited.".to_string()),
            "ports" => Err("Command 'ports' is blocked in router-lab mode: port scanning is strictly prohibited.".to_string()),
            "audit" => Err("Command 'audit' is blocked in router-lab mode: active network auditing is strictly prohibited.".to_string()),
            "add" => Err("Command 'add' is blocked in router-lab mode: manual target addition is prohibited.".to_string()),
            "scope" => Err("Command 'scope' is blocked in router-lab mode: scope mutations are prohibited.".to_string()),
            "free" | "unblock" | "unlimit" | "release" => Err("Command 'free/unblock' is blocked in router-lab mode: local target modification is prohibited.".to_string()),
            "block" => Err("Command 'block' is blocked in router-lab mode: local network enforcement is disabled.".to_string()),
            "limit" => Err("Command 'limit' is blocked in router-lab mode: local traffic limiting is disabled.".to_string()),
            "simulate" => Err("Command 'simulate' is blocked in router-lab mode: network simulation is disabled.".to_string()),
            "export" => Err("Top-level 'export' is disabled in router-lab mode. Use 'router export-evidence' for read-only router evidence export.".to_string()),
            other => Err(format!(
                "Command '{}' is not allowed in router-lab mode (default-deny policy). Type 'help' for allowed read-only commands.",
                other
            )),
        }
    }

    /// Dispatches a single command string.
    /// Returns false if session should terminate (exit/quit), true to continue.
    pub fn dispatch_command(&mut self, input: &str) -> bool {
        let args: Vec<&str> = input.split_whitespace().collect();
        if args.is_empty() {
            return true;
        }

        if self.is_router_lab {
            if let Err(err_msg) = self.is_command_allowed_in_router_lab(&args) {
                println!("{} {}", "[ERR]".red().bold(), err_msg);
                return true;
            }
        }

        match args[0].to_lowercase().as_str() {
            "scan" => self.handle_scan(&args[1..]),
            "hosts" | "devices" | "targets" | "list" | "ls" => self.handle_hosts(),
            "scope" => self.handle_scope(&args[1..]),
            "ports" => self.handle_ports(&args[1..]),
            "audit" => self.handle_audit(&args[1..]),
            "simulate" => self.handle_simulate(&args[1..]),
            "export" => self.handle_export(&args[1..]),
            "limit" => self.handle_limit(&args[1..]),
            "block" => self.handle_block(&args[1..]),
            "free" | "unblock" | "unlimit" | "release" => self.handle_free(&args[1..]),
            "status" => self.handle_status(),
            "state" => self.handle_state(&args[1..]),
            "upgrade" | "update" => self.handle_upgrade(),
            "blockmode" | "spoofer" => self.handle_blockmode(&args[1..]),
            "mode" => {
                if args.len() > 1
                    && (args[1].eq_ignore_ascii_case("strict")
                        || args[1].eq_ignore_ascii_case("permissive"))
                {
                    let sub_cmd = format!("strict {}", args[1..].join(" "));
                    self.dispatch_command(&sub_cmd);
                } else {
                    self.handle_blockmode(&args[1..]);
                }
            }
            "strict" => {
                let sub = args.get(1).map(|s| s.to_lowercase()).unwrap_or_default();
                let sub2 = args.get(2).map(|s| s.to_lowercase()).unwrap_or_default();
                if sub == "off"
                    || sub == "false"
                    || sub == "disable"
                    || (sub == "mode" && (sub2 == "off" || sub2 == "false" || sub2 == "disable"))
                {
                    self.scope.set_strict(false);
                    self.persistent_state.scope = Some(self.scope.clone());
                    let _ = self.persistent_state.save();
                    println!(
                        "{} Strict mode DISABLED (Permissive LAN enforcement active).",
                        "OK".green().bold()
                    );
                } else if sub == "on"
                    || sub == "true"
                    || sub == "enable"
                    || (sub == "mode" && (sub2 == "on" || sub2 == "true" || sub2 == "enable"))
                {
                    self.scope.set_strict(true);
                    self.persistent_state.scope = Some(self.scope.clone());
                    let _ = self.persistent_state.save();
                    println!(
                        "{} Strict mode ENABLED (Only authorized CIDRs allowed).",
                        "OK".green().bold()
                    );
                } else {
                    println!(
                        "Strict Mode Status: {}",
                        if self.scope.strict_mode {
                            "ENABLED (Strict)".yellow().bold()
                        } else {
                            "DISABLED (Permissive)".green().bold()
                        }
                    );
                    println!("Usage: 'strict off' (or 'strict on') to toggle.");
                }
            }
            "permissive" | "unrestrict" => {
                self.scope.set_strict(false);
                self.persistent_state.scope = Some(self.scope.clone());
                let _ = self.persistent_state.save();
                println!(
                    "{} Permissive mode ENABLED (All private LANs permitted).",
                    "OK".green().bold()
                );
            }
            "add" => self.handle_add(&args[1..]),
            "router" => self.handle_router(&args[1..]),
            "nic" | "adapter" => self.handle_nic(&args[1..]),
            "clear" | "cls" => {
                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
                let _ = io::stdout().flush();
            }
            "help" | "?" => self.print_help(),
            "quit" | "exit" => {
                self.shutdown();
                println!("Exiting rustrict. Active session stopped.");
                return false;
            }
            cmd => println!("{}: command not found. Type 'help' for commands.", cmd),
        }
        true
    }

    pub fn run_interactive(&mut self) {
        let stdin = io::stdin();

        loop {
            print!("{} ", "rustrict >".bright_red().bold());
            let _ = io::stdout().flush();

            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) => {
                    // EOF reached (e.g. pipe closed or Ctrl+Z/Ctrl+D)
                    println!("\nEOF received. Shutting down cleanly...");
                    self.shutdown();
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error reading input: {}. Shutting down cleanly...", e);
                    self.shutdown();
                    break;
                }
            }

            let input = line.trim().trim_start_matches('\u{feff}').trim();
            if input.is_empty() {
                continue;
            }

            if !self.dispatch_command(input) {
                break;
            }
        }
    }

    pub fn handle_scan(&mut self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Active network scanning is disabled in router-lab mode.",
                "[ERR]".red().bold()
            );
            return;
        }
        let is_fresh = args.contains(&"--fresh");
        if is_fresh {
            println!(
                "{}",
                "Performing clean fresh scan (bypassing cache)...".bright_yellow()
            );
        } else {
            println!("{}", "Scanning subnet for online hosts...".yellow());
        }
        let t0 = std::time::Instant::now();

        let mut custom_range = None;
        if let Some(pos) = args.iter().position(|&a| a == "--range") {
            if pos + 1 < args.len() {
                let parts: Vec<&str> = args[pos + 1].split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) =
                        (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<Ipv4Addr>())
                    {
                        custom_range = Some((start, end));
                    }
                }
            }
        }

        let progress_cb = |scanned: usize, total: usize, discovered: usize| {
            let width = 28;
            let ratio = if total > 0 {
                (scanned as f64) / (total as f64)
            } else {
                1.0
            };
            let filled = ((ratio * width as f64) as usize).min(width);
            let empty = width - filled;

            let bar = format!(
                "{}{}",
                "█".repeat(filled).bright_cyan(),
                "░".repeat(empty).white().dimmed()
            );
            let percent = (ratio * 100.0) as u32;

            print!(
                "\r  [{}] {:>3}% ({}/{}) | Discovered: {} hosts  ",
                bar,
                percent,
                scanned,
                total,
                discovered.to_string().bright_green().bold()
            );
            let _ = io::stdout().flush();
        };

        let new_hosts = if let Some((start, end)) = custom_range {
            self.scanner.scan_range(start, end, is_fresh, progress_cb)
        } else {
            self.scanner.scan_subnet(is_fresh, progress_cb)
        };

        println!(); // Move cursor past progress bar line
        let elapsed = t0.elapsed();
        println!(
            "{} Discovered {} host(s) in {:.2}s\n",
            "OK".green().bold(),
            new_hosts.len().to_string().cyan().bold(),
            elapsed.as_secs_f64()
        );

        self.reconcile_hosts(new_hosts, is_fresh);
        render_hosts_table(&self.hosts);

        if args.contains(&"--ports") {
            println!(
                "\n{} Performing service enumeration on discovered hosts...",
                "[SCAN]".cyan().bold()
            );
            let online_ips: Vec<Ipv4Addr> = self
                .hosts
                .iter()
                .filter(|h| h.online)
                .map(|h| h.ip)
                .collect();
            let top_ports = crate::probes::get_top_port_numbers();
            for ip in online_ips {
                let open = crate::probes::scan_host_ports(
                    ip,
                    &top_ports,
                    std::time::Duration::from_millis(500),
                    |_, _| {},
                );
                if !open.is_empty() {
                    render_services_table(ip, &open);
                    self.services.insert(ip, open);
                }
            }
        }
    }

    fn handle_hosts(&mut self) {
        // Merge passive discoveries from sniffer
        for (ip, mac, name) in self.sniffer.get_all_entries() {
            if ip == self.iface.gateway
                || (self.iface.gateway_mac != MacAddress::ZERO && mac == self.iface.gateway_mac)
            {
                continue;
            }
            if let Some(existing) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                if existing.mac == mac || existing.mac.is_zero() {
                    existing.mac = mac;
                    existing.name = name;
                    existing.name_source = crate::types::NameSource::Dhcp;
                    existing.online = true;
                }
            } else if !mac.is_zero() {
                let id = self.hosts.len();
                let vendor = crate::resolver::oui::lookup_vendor(&mac).to_string();
                let mut new_h =
                    Host::with_source(id, ip, mac, name, crate::types::NameSource::Dhcp, vendor);
                new_h.online = true;
                self.hosts.push(new_h);
            }
        }

        if self.hosts.is_empty() {
            if self.is_router_lab {
                println!("No hosts in inventory (active scanning disabled in router-lab mode).");
            } else {
                println!("No hosts discovered yet. Run 'scan' first.");
            }
            return;
        }

        // Sort by IP ascending and re-index
        self.hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, h) in self.hosts.iter_mut().enumerate() {
            h.id = i;
        }

        render_hosts_table(&self.hosts);
    }

    pub fn handle_limit(&mut self, args: &[&str]) {
        if args.len() < 2 {
            println!("Usage: limit <id|ip|all> <rate> [--upload] [--download]");
            return;
        }

        // 1. Guard against router-lab mode
        if self.is_router_lab {
            println!(
                "{} Local enforcement command 'limit' is disabled in router-lab mode. Router-lab mode is strictly read-only for local Layer 2/3 interfaces.",
                "[ERR]".red().bold()
            );
            return;
        }

        let rate = match BitRate::from_str_custom(args[1]) {
            Ok(r) => r,
            Err(e) => {
                println!("{} Error parsing rate: {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        let mut dir = Direction::Both;
        if args.contains(&"--upload") && !args.contains(&"--download") {
            dir = Direction::Outgoing;
        } else if args.contains(&"--download") && !args.contains(&"--upload") {
            dir = Direction::Incoming;
        }

        // 2. Fail-closed injection check
        if !self.spoofer.has_sender() {
            println!(
                "{} Aborting operation: Raw Layer 2 packet injection sender is not initialized (Npcap unavailable).",
                "[ERR]".red().bold()
            );
            return;
        }

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        // 3. Pre-validate target scope and exclusions before mutating state or enabling forwarding
        let validator = self.admission_validator();
        let mut target_hosts = Vec::new();
        for id in ids {
            if let Some(host) = self.hosts.iter().find(|h| h.id == id) {
                if let Err(reason) = validator.validate_target(
                    &host.ip,
                    Some(&host.mac),
                    AdmissionOperation::LocalEnforcement,
                ) {
                    if args[0].eq_ignore_ascii_case("all") {
                        continue;
                    }
                    println!(
                        "{} Scope / Admission Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }
                target_hosts.push(host.clone());
            }
        }

        if target_hosts.is_empty() {
            println!(
                "{} No valid in-scope target hosts to limit.",
                "[WARN]".yellow().bold()
            );
            return;
        }

        // 4. Fail-closed forwarding check: Abort operation if forwarding cannot be enabled
        if let Err(e) = crate::platform::ensure_scoped_forwarding_enabled(&self.iface.name) {
            println!(
                "{} Aborting operation: Failed to enable scoped IP forwarding on {}: {}",
                "[ERR]".red().bold(),
                self.iface.name,
                e
            );
            return;
        }

        // 5. Atomic multi-target activation with transactional rollback
        for host in &mut target_hosts {
            host.status = HostStatus::Limited(rate, dir);
        }
        let mut activated = Vec::new();
        let mut failure = None;
        for host in &target_hosts {
            match self.spoofer.add(host.clone()) {
                Ok(()) => {
                    self.limiter.limit(host.ip, dir, rate);
                    activated.push(host.clone());
                }
                Err(err) => {
                    failure = Some((host.ip, err));
                    break;
                }
            }
        }

        if let Some((failed_ip, err)) = failure {
            for act in &activated {
                self.spoofer.remove(&act.ip);
                self.limiter.unlimit(&act.ip);
            }
            println!(
                "{} Enforcement transaction failed on {}: {}. Rolled back {} previously activated target(s). Zero state mutated.",
                "[ERR]".red().bold(),
                failed_ip,
                err,
                activated.len()
            );
            return;
        }

        // 6. Mutate host state only after verified transactional success
        for host in target_hosts {
            if let Some(h) = self.hosts.iter_mut().find(|h| h.id == host.id) {
                h.status = HostStatus::Limited(rate, dir);
            }
            self.spoofer
                .update_status(&host.ip, HostStatus::Limited(rate, dir));
            println!(
                "{} Limited {} to {} ({})",
                "OK".green().bold(),
                host.ip,
                rate,
                dir.pretty()
            );
        }
    }

    pub fn handle_block(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: block <id|ip|all> [--upload] [--download]");
            return;
        }

        // 1. Guard against router-lab mode
        if self.is_router_lab {
            println!(
                "{} Local enforcement command 'block' is disabled in router-lab mode. Router-lab mode is strictly read-only for local Layer 2/3 interfaces.",
                "[ERR]".red().bold()
            );
            return;
        }

        let mut dir = Direction::Both;
        if args.contains(&"--upload") && !args.contains(&"--download") {
            dir = Direction::Outgoing;
        } else if args.contains(&"--download") && !args.contains(&"--upload") {
            dir = Direction::Incoming;
        }

        // 2. Fail-closed injection check
        if !self.spoofer.has_sender() {
            println!(
                "{} Aborting operation: Raw Layer 2 packet injection sender is not initialized (Npcap unavailable).",
                "[ERR]".red().bold()
            );
            return;
        }

        let target_tokens: Vec<&str> = args
            .iter()
            .filter(|&&a| !a.starts_with("--"))
            .cloned()
            .collect();
        if target_tokens.is_empty() {
            println!("Usage: block <id|ip|all> [--upload] [--download]");
            return;
        }
        let combined_target = target_tokens.join(",");
        let ids = match self.resolve_targets(&combined_target) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        // 3. Pre-validate target scope and exclusions before mutating state or enabling forwarding
        let validator = self.admission_validator();
        let mut target_hosts = Vec::new();
        for id in ids {
            if let Some(host) = self.hosts.iter().find(|h| h.id == id) {
                if let Err(reason) = validator.validate_target(
                    &host.ip,
                    Some(&host.mac),
                    AdmissionOperation::LocalEnforcement,
                ) {
                    if args[0].eq_ignore_ascii_case("all") {
                        continue;
                    }
                    println!(
                        "{} Scope / Admission Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }
                target_hosts.push(host.clone());
            }
        }

        if target_hosts.is_empty() {
            println!(
                "{} No valid in-scope target hosts to block.",
                "[WARN]".yellow().bold()
            );
            return;
        }

        // 4. Fail-closed forwarding check: Abort operation if forwarding cannot be enabled
        if let Err(e) = crate::platform::ensure_scoped_forwarding_enabled(&self.iface.name) {
            println!(
                "{} Aborting operation: Failed to enable scoped IP forwarding on {}: {}",
                "[ERR]".red().bold(),
                self.iface.name,
                e
            );
            return;
        }

        // 5. Atomic multi-target activation with transactional rollback
        for host in &mut target_hosts {
            host.status = HostStatus::Blocked(dir);
        }
        let mut activated = Vec::new();
        let mut failure = None;
        for host in &target_hosts {
            match self.spoofer.add(host.clone()) {
                Ok(()) => {
                    self.limiter.block(host.ip, dir);
                    activated.push(host.clone());
                }
                Err(err) => {
                    failure = Some((host.ip, err));
                    break;
                }
            }
        }

        if let Some((failed_ip, err)) = failure {
            for act in &activated {
                self.spoofer.remove(&act.ip);
                self.limiter.unlimit(&act.ip);
            }
            println!(
                "{} Enforcement transaction failed on {}: {}. Rolled back {} previously activated target(s). Zero state mutated.",
                "[ERR]".red().bold(),
                failed_ip,
                err,
                activated.len()
            );
            return;
        }

        // 6. Mutate host state and persistent records only after verified transactional success
        for host in target_hosts {
            if let Some(h) = self.hosts.iter_mut().find(|h| h.id == host.id) {
                h.status = HostStatus::Blocked(dir);
                h.persistent_block = true;
                self.persistent_state.add_blocked(h, dir);
            }
            self.spoofer
                .update_status(&host.ip, HostStatus::Blocked(dir));
            println!(
                "{} Blocked {} ({}) [Persistent]",
                "OK".green().bold(),
                host.ip,
                dir.pretty()
            );
        }
    }

    pub fn handle_free(&mut self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Local target modification is disabled in router-lab mode.",
                "[ERR]".red().bold()
            );
            return;
        }

        if args.is_empty() {
            println!("Usage: free <id|ip|all> (or unblock <id|ip|all>)");
            return;
        }

        let target_tokens: Vec<&str> = args
            .iter()
            .filter(|&&a| !a.starts_with("--"))
            .cloned()
            .collect();
        if target_tokens.is_empty() {
            println!("Usage: free <id|ip|all> (or unblock <id|ip|all>)");
            return;
        }
        let combined_target = target_tokens.join(",");
        let ids = match self.resolve_targets(&combined_target) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        for id in ids {
            if let Some(host) = self.hosts.iter_mut().find(|h| h.id == id) {
                host.status = HostStatus::Free;
                host.persistent_block = false;
                self.persistent_state.remove_blocked(&host.ip);
                self.spoofer.remove(&host.ip);
                self.limiter.unlimit(&host.ip);
                println!("{} Freed {}", "OK".green().bold(), host.ip);
            }
        }
    }

    pub fn handle_add(&mut self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Manual target addition is disabled in router-lab mode.",
                "[ERR]".red().bold()
            );
            return;
        }

        if args.is_empty() {
            println!("Usage: add <ip> [--mac <mac>]");
            return;
        }

        let ip = match args[0].parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(_) => {
                println!("{} Invalid IP address: {}", "[ERR]".red().bold(), args[0]);
                return;
            }
        };

        let mut mac = MacAddress::ZERO;
        if args.len() >= 3 && args[1] == "--mac" {
            if let Ok(m) = args[2].parse::<MacAddress>() {
                mac = m;
            }
        }

        if mac == MacAddress::ZERO {
            if let Some(resolved_mac) = crate::platform::send_arp(ip) {
                mac = resolved_mac;
            }
        }

        let identity =
            crate::resolver::resolve_identity(ip, &mac, self.iface.ip, self.iface.gateway);

        // Check if host already exists; update it instead of creating duplicates
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.ip == ip) {
            existing.mac = mac;
            existing.name = identity.hostname;
            existing.name_source = identity.source;
            existing.vendor = identity.vendor;
            println!(
                "{} Updated existing host {} ({})",
                "OK".green().bold(),
                existing.ip,
                existing.mac
            );
        } else {
            let id = self.hosts.len();
            let host = Host::with_source(
                id,
                ip,
                mac,
                identity.hostname,
                identity.source,
                identity.vendor,
            );
            println!(
                "{} Added host {} ({})",
                "OK".green().bold(),
                host.ip,
                host.mac
            );
            self.hosts.push(host);
        }

        self.hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, h) in self.hosts.iter_mut().enumerate() {
            h.id = i;
        }
    }

    /// Reconciles discovered hosts with known inventory.
    /// In fresh mode: purges offline unmanaged devices, while strictly preserving blocked/limited devices.
    /// In standard mode: updates live reachability (online/offline) for all devices.
    fn reconcile_hosts(&mut self, new_hosts: Vec<Host>, is_fresh: bool) {
        if is_fresh {
            // Clean rescan mode:
            // Remove unmanaged/free devices that did not respond in this scan.
            // Preserves any device with an active/persistent block or rate-limit.
            self.hosts.retain(|h| {
                h.persistent_block
                    || h.status != HostStatus::Free
                    || new_hosts
                        .iter()
                        .any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac))
            });
        }

        // Update reachability flags for remaining existing hosts
        for h in &mut self.hosts {
            let is_alive = new_hosts
                .iter()
                .any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac));
            h.online = is_alive;
        }

        let has_persistent_blocks = self.hosts.iter().any(|h| h.persistent_block);
        let forwarding_ok = if has_persistent_blocks && !self.is_router_lab {
            match crate::platform::ensure_scoped_forwarding_enabled(&self.iface.name) {
                Ok(_) => true,
                Err(e) => {
                    eprintln!(
                        "{} Failed to enable scoped IP forwarding for persistent blocks on {}: {}. Deactivating enforcement.",
                        "[ERR]".bright_red().bold(),
                        self.iface.name,
                        e
                    );
                    // Deactivate in-memory spoofer & limiter to prevent traffic blackholing without forwarding
                    for h in self.hosts.iter_mut() {
                        if h.persistent_block {
                            if let HostStatus::Blocked(dir) = h.status {
                                self.spoofer.remove(&h.ip);
                                self.limiter.unlimit(&h.ip);
                                h.status = HostStatus::PersistedInactive(dir);
                            }
                        }
                    }
                    false
                }
            }
        } else {
            true
        };

        let validator = TargetAdmissionValidator::new(
            self.iface.ip,
            self.iface.mac,
            self.iface.gateway,
            self.iface.gateway_mac,
            &self.scope,
        );

        // Upsert newly discovered/confirmed hosts
        for new_h in new_hosts {
            if let Some(existing) = self
                .hosts
                .iter_mut()
                .find(|h| (h.mac != MacAddress::ZERO && h.mac == new_h.mac) || h.ip == new_h.ip)
            {
                existing.ip = new_h.ip;
                existing.mac = new_h.mac;
                existing.online = true;
                if new_h.name_source != crate::types::NameSource::Unresolved {
                    existing.name = new_h.name;
                    existing.name_source = new_h.name_source;
                }
                if existing.vendor.is_empty() || existing.vendor == "Generic Network Device" {
                    existing.vendor = new_h.vendor;
                }
                // Ensure persistent block is continuously enforced only if forwarding is verified and not router-lab mode
                if existing.persistent_block && forwarding_ok && !self.is_router_lab {
                    let dir = match existing.status {
                        HostStatus::Blocked(dir) => Some(dir),
                        HostStatus::PersistedInactive(dir) => Some(dir),
                        _ => None,
                    };
                    if let Some(dir) = dir {
                        if self.spoofer.has_sender()
                            && validator
                                .validate_target(
                                    &existing.ip,
                                    Some(&existing.mac),
                                    AdmissionOperation::LocalEnforcement,
                                )
                                .is_ok()
                        {
                            if self.spoofer.add(existing.clone()).is_ok() {
                                self.limiter.block(existing.ip, dir);
                                existing.status = HostStatus::Blocked(dir);
                            } else {
                                existing.status = HostStatus::PersistedInactive(dir);
                            }
                        } else {
                            existing.status = HostStatus::PersistedInactive(dir);
                        }
                    }
                }
            } else {
                let id = self.hosts.len();
                let mut added = new_h;
                added.id = id;
                added.online = true;
                self.hosts.push(added);
            }
        }

        self.hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, h) in self.hosts.iter_mut().enumerate() {
            h.id = i;
        }
    }

    pub fn handle_scope(&mut self, args: &[&str]) {
        if self.is_router_lab {
            if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
                render_scope_table(&self.scope);
            } else {
                println!(
                    "{} Scope mutations are disabled in router-lab mode.",
                    "[ERR]".red().bold()
                );
            }
            return;
        }

        if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
            render_scope_table(&self.scope);
            return;
        }

        match args[0].to_lowercase().as_str() {
            "add" => {
                if args.len() < 2 {
                    println!("Usage: scope add <cidr|all|local> (e.g. scope add all, scope add 192.168.1.0/24)");
                    return;
                }
                if args[1].eq_ignore_ascii_case("all") {
                    self.add_all_private_cidrs_to_scope();
                    return;
                }
                if args[1].eq_ignore_ascii_case("local") {
                    self.add_local_interface_to_scope();
                    return;
                }

                let raw_cidr = args[1].trim();
                let cidr_to_parse = if raw_cidr.contains('/') {
                    raw_cidr.to_string()
                } else if raw_cidr.ends_with(".0") {
                    format!("{}/24", raw_cidr)
                } else {
                    format!("{}/32", raw_cidr)
                };

                match cidr_to_parse.parse::<Ipv4Cidr>() {
                    Ok(cidr) => {
                        self.scope.add_cidr_direct(cidr.clone());
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Added CIDR {} to operational scope", "OK".green().bold(), cidr);
                    }
                    Err(e) => println!("{} Failed to parse CIDR '{}': {}", "[ERR]".red().bold(), raw_cidr, e),
                }
            }
            "all" => {
                self.add_all_private_cidrs_to_scope();
            }
            "local" | "auto" => {
                self.add_local_interface_to_scope();
            }
            "reset" => {
                self.reset_scope_to_defaults();
            }
            "clear" => {
                self.scope.allowed_cidrs.clear();
                self.scope.excluded_ips.clear();
                self.scope.excluded_macs.clear();
                self.persistent_state.scope = Some(self.scope.clone());
                let _ = self.persistent_state.save();
                println!("{} Cleared all operational scope CIDRs and exclusions", "OK".green().bold());
            }
            "on" | "enable" => {
                self.scope.set_strict(true);
                self.persistent_state.scope = Some(self.scope.clone());
                let _ = self.persistent_state.save();
                println!("{} Scope strict mode ENABLED (out-of-scope targets blocked)", "OK".green().bold());
            }
            "off" | "permissive" | "disable" => {
                self.scope.set_strict(false);
                self.persistent_state.scope = Some(self.scope.clone());
                let _ = self.persistent_state.save();
                println!("{} Scope strict mode DISABLED (Permissive LAN enforcement active)", "OK".green().bold());
            }
            "remove" | "rm" => {
                if args.len() < 2 {
                    println!("Usage: scope remove <cidr>");
                    return;
                }
                match args[1].parse::<Ipv4Cidr>() {
                    Ok(cidr) => {
                        self.scope.remove_cidr_direct(&cidr);
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Removed CIDR {} from scope", "OK".green().bold(), cidr);
                    }
                    Err(e) => println!("{} Failed to parse CIDR: {}", "[ERR]".red().bold(), e),
                }
            }
            "exclude-ip" => {
                if args.len() < 2 {
                    println!("Usage: scope exclude-ip <ip>");
                    return;
                }
                match args[1].parse::<Ipv4Addr>() {
                    Ok(ip) => {
                        self.scope.exclude_ip(ip);
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Excluded IP {} from scope actions", "OK".green().bold(), ip);
                    }
                    Err(e) => println!("{} Failed to parse IP: {}", "[ERR]".red().bold(), e),
                }
            }
            "exclude-mac" => {
                if args.len() < 2 {
                    println!("Usage: scope exclude-mac <mac>");
                    return;
                }
                match args[1].parse::<MacAddress>() {
                    Ok(mac) => {
                        self.scope.exclude_mac(mac);
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Excluded MAC {} from scope actions", "OK".green().bold(), mac);
                    }
                    Err(e) => println!("{} Failed to parse MAC: {}", "[ERR]".red().bold(), e),
                }
            }
            "strict" => {
                if args.len() < 2 {
                    println!("Usage: scope strict <on|off>");
                    return;
                }
                match args[1].to_lowercase().as_str() {
                    "on" | "true" | "1" => {
                        self.scope.set_strict(true);
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Scope strict mode ENABLED (out-of-scope targets blocked)", "OK".green().bold());
                    }
                    "off" | "false" | "0" => {
                        self.scope.set_strict(false);
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Scope strict mode DISABLED", "OK".green().bold());
                    }
                    _ => println!("Invalid argument. Use 'scope strict on' or 'scope strict off'"),
                }
            }
            _ => println!("Usage: scope [status | add <cidr|all|local> | all | reset | clear | strict <on|off> | exclude-ip <ip> | exclude-mac <mac>]"),
        }
    }

    pub fn add_all_private_cidrs_to_scope(&mut self) {
        let subnets = [
            ("10.0.0.0", 8),
            ("172.16.0.0", 12),
            ("192.168.0.0", 16),
            ("100.64.0.0", 10),
            ("169.254.0.0", 16),
        ];
        for (ip_str, prefix) in subnets {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if let Ok(cidr) = Ipv4Cidr::new(ip, prefix) {
                    if !self.scope.allowed_cidrs.contains(&cidr) {
                        self.scope.add_cidr_direct(cidr);
                    }
                }
            }
        }
        let iface_prefix = u32::from(self.iface.netmask).count_ones() as u8;
        let iface_prefix = if iface_prefix > 0 && iface_prefix <= 32 {
            iface_prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(self.iface.ip, iface_prefix) {
            if !self.scope.allowed_cidrs.contains(&local_cidr) {
                self.scope.add_cidr_direct(local_cidr);
            }
        }

        self.persistent_state.scope = Some(self.scope.clone());
        let _ = self.persistent_state.save();

        println!(
            "{} Added all standard private network boundaries to scope:",
            "OK".green().bold()
        );
        println!("     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16");
        println!("     All LAN devices are now authorized for management.");
    }

    pub fn add_local_interface_to_scope(&mut self) {
        let prefix = u32::from(self.iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        match Ipv4Cidr::new(self.iface.ip, prefix) {
            Ok(local_cidr) => {
                if !self.scope.allowed_cidrs.contains(&local_cidr) {
                    self.scope.add_cidr_direct(local_cidr.clone());
                }
                self.persistent_state.scope = Some(self.scope.clone());
                let _ = self.persistent_state.save();
                println!(
                    "{} Added local interface subnet {} to operational scope",
                    "OK".green().bold(),
                    local_cidr
                );
            }
            Err(e) => println!(
                "{} Failed to compute local CIDR: {}",
                "[ERR]".red().bold(),
                e
            ),
        }
    }

    pub fn reset_scope_to_defaults(&mut self) {
        self.scope = ScopeManager::default();
        let prefix = u32::from(self.iface.netmask).count_ones() as u8;
        let prefix = if prefix > 0 && prefix <= 32 {
            prefix
        } else {
            24
        };
        if let Ok(local_cidr) = Ipv4Cidr::new(self.iface.ip, prefix) {
            self.scope.add_cidr_direct(local_cidr);
        }
        self.persistent_state.scope = Some(self.scope.clone());
        let _ = self.persistent_state.save();
        println!(
            "{} Scope reset to active adapter defaults (strict mode enabled)",
            "OK".green().bold()
        );
    }

    pub fn handle_status(&self) {
        println!(
            "{}",
            "============================================================".cyan()
        );
        println!(
            " {}",
            "Rustrict System & Network Status".bright_cyan().bold()
        );
        println!(
            "{}",
            "============================================================".cyan()
        );
        println!(
            "  {:<26} {}",
            "Active Network Adapter:",
            self.iface.name.bright_white().bold()
        );
        println!(
            "  {:<26} {} ({})",
            "Local Controller IP:", self.iface.ip, self.iface.mac
        );
        println!(
            "  {:<26} {} ({})",
            "Default Gateway:", self.iface.gateway, self.iface.gateway_mac
        );
        println!("  {:<26} {}", "Subnet Netmask:", self.iface.netmask);
        println!(
            "  {:<26} {}",
            "Operation Mode:",
            if self.is_router_lab {
                "READ-ONLY Router-Lab (Safe)".bright_yellow().bold()
            } else {
                "ACTIVE Local Enforcement (Privileged)"
                    .bright_green()
                    .bold()
            }
        );
        println!(
            "  {:<26} {}",
            "Scope Strict Mode:",
            if self.scope.strict_mode {
                "ENABLED (targets strictly bounded)".yellow()
            } else {
                "DISABLED (all LAN targets permitted)".green()
            }
        );
        println!(
            "  {:<26} {} defined",
            "Authorized Boundaries:",
            self.scope.allowed_cidrs.len()
        );
        for (i, c) in self.scope.allowed_cidrs.iter().enumerate() {
            if i < 5 {
                println!("    - {}", c);
            } else if i == 5 {
                println!(
                    "    ... and {} more (run 'scope status' to view all)",
                    self.scope.allowed_cidrs.len() - 5
                );
                break;
            }
        }
        let online_count = self.hosts.iter().filter(|h| h.online).count();
        let blocked_count = self
            .hosts
            .iter()
            .filter(|h| matches!(h.status, HostStatus::Blocked(_)))
            .count();
        let limited_count = self
            .hosts
            .iter()
            .filter(|h| matches!(h.status, HostStatus::Limited(_, _)))
            .count();
        println!(
            "  {:<26} {} total ({} online)",
            "Discovered Devices:",
            self.hosts.len(),
            online_count.to_string().bright_green()
        );
        println!(
            "  {:<26} {} blocked, {} rate-limited",
            "Active Enforcements:",
            blocked_count.to_string().bright_red(),
            limited_count.to_string().bright_yellow()
        );
        println!(
            "  {:<26} {}",
            "Packet Injection (Npcap):",
            if self.spoofer.has_sender() {
                "READY (Sender initialized)".bright_green()
            } else {
                "UNAVAILABLE (Read-only or Npcap missing)".red()
            }
        );
        println!(
            "{}",
            "============================================================".cyan()
        );
    }

    pub fn handle_state(&mut self, args: &[&str]) {
        if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
            println!("Persistent State Status:");
            println!(
                "  Persisted Blocked Devices: {}",
                self.persistent_state.blocked_hosts.len()
            );
            for b in &self.persistent_state.blocked_hosts {
                println!("    - {} [{}] ({})", b.ip, b.mac, b.direction);
            }
            if let Some(ref sc) = self.persistent_state.scope {
                println!("  Persisted Scope Boundaries: {}", sc.allowed_cidrs.len());
                println!("  Persisted Strict Mode:     {}", sc.strict_mode);
            }
            return;
        }

        match args[0].to_lowercase().as_str() {
            "clear" | "reset" => {
                self.persistent_state.blocked_hosts.clear();
                self.persistent_state.scope = None;
                if let Err(e) = self.persistent_state.save() {
                    println!("{} Failed to clear state file: {}", "[ERR]".red().bold(), e);
                } else {
                    println!(
                        "{} Successfully cleared persisted blocks and state file",
                        "OK".green().bold()
                    );
                }
            }
            _ => println!("Usage: state [status | clear]"),
        }
    }

    pub fn handle_ports(&mut self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Port scanning is disabled in router-lab mode.",
                "[ERR]".red().bold()
            );
            return;
        }

        if args.is_empty() {
            println!("Usage: ports <id|ip|all> [ports-range] (e.g. ports 1 80,443,8000-8080)");
            return;
        }

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        let ports = if args.len() >= 2 {
            match crate::probes::parse_ports_arg(args[1]) {
                Ok(p) => p,
                Err(e) => {
                    println!("{} Error parsing ports: {}", "[ERR]".red().bold(), e);
                    return;
                }
            }
        } else {
            crate::probes::get_top_port_numbers()
        };

        for id in ids {
            if let Some(host) = self.hosts.iter().find(|h| h.id == id).cloned() {
                if let Err(reason) = self.scope.validate_target(&host.ip, Some(&host.mac)) {
                    println!(
                        "{} Scope Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }

                println!(
                    "{} Scanning {} ports on {} ({}) with service identification...",
                    "[SCAN]".cyan().bold(),
                    ports.len(),
                    host.ip,
                    host.mac
                );

                let open_services = crate::probes::scan_host_ports(
                    host.ip,
                    &ports,
                    std::time::Duration::from_millis(600),
                    |_, _| {},
                );
                render_services_table(host.ip, &open_services);
                self.services.insert(host.ip, open_services);
            }
        }
    }

    pub fn handle_audit(&mut self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Active network auditing is disabled in router-lab mode.",
                "[ERR]".red().bold()
            );
            return;
        }

        if args.is_empty() {
            println!("Usage: audit <id|ip|all>");
            return;
        }

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        for id in ids {
            if let Some(host) = self.hosts.iter().find(|h| h.id == id).cloned() {
                if let Err(reason) = self.scope.validate_target(&host.ip, Some(&host.mac)) {
                    println!(
                        "{} Scope Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }

                println!(
                    "{} Performing active protocol posture audit on {}...",
                    "[AUDIT]".cyan().bold(),
                    host.ip
                );

                let mut host_findings = Vec::new();

                // TLS Audit on 443 + any discovered TLS ports
                let mut tls_ports = vec![443];
                if let Some(svcs) = self.services.get(&host.ip) {
                    for s in svcs {
                        let name_lower = s.service_name.to_lowercase();
                        if (name_lower.contains("ssl")
                            || name_lower.contains("https")
                            || name_lower.contains("tls"))
                            && !tls_ports.contains(&s.port)
                        {
                            tls_ports.push(s.port);
                        }
                    }
                }

                for p in tls_ports {
                    let tf = crate::probes::audit_tls_posture(host.ip, p);
                    host_findings.extend(tf);
                }

                // SMB Audit on 445
                let sf = crate::probes::audit_smb_posture(host.ip);
                host_findings.extend(sf);

                render_findings_table(&host_findings);

                for f in host_findings {
                    if !self.findings.iter().any(|ex| {
                        ex.rule_id == f.rule_id && ex.target_ip == f.target_ip && ex.port == f.port
                    }) {
                        self.findings.push(f);
                    }
                }
            }
        }
    }

    pub fn handle_simulate(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: simulate <id|ip|all> [drop <0-100>] [delay <ms>] [jitter <ms>] OR simulate <id|ip|all> clear");
            return;
        }

        // 1. Guard against router-lab mode
        if self.is_router_lab {
            println!(
                "{} Local fault simulation command 'simulate' is disabled in router-lab mode. Router-lab mode is strictly read-only for local Layer 2/3 interfaces.",
                "[ERR]".red().bold()
            );
            return;
        }

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        if args.len() >= 2 && args[1].eq_ignore_ascii_case("clear") {
            for id in ids {
                if let Some(host) = self.hosts.iter().find(|h| h.id == id) {
                    self.limiter.clear_fault(&host.ip);
                    println!(
                        "{} Cleared fault simulation for {}",
                        "OK".green().bold(),
                        host.ip
                    );
                }
            }
            return;
        }

        let mut drop_pct: u8 = 0;
        let mut delay_ms: u32 = 0;
        let mut jitter_ms: u32 = 0;

        let mut i = 1;
        while i < args.len() {
            match args[i].to_lowercase().as_str() {
                "drop" => {
                    if let Some(val) = args.get(i + 1) {
                        if let Ok(pct) = val.parse::<u8>() {
                            drop_pct = pct.min(100);
                        }
                        i += 1;
                    }
                }
                "delay" => {
                    if let Some(val) = args.get(i + 1) {
                        if let Ok(d) = val.parse::<u32>() {
                            delay_ms = d;
                        }
                        i += 1;
                    }
                }
                "jitter" => {
                    if let Some(val) = args.get(i + 1) {
                        if let Ok(j) = val.parse::<u32>() {
                            jitter_ms = j;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        let profile = FaultProfile::new(drop_pct, delay_ms, jitter_ms);

        // 2. Fail-closed injection check
        if !self.spoofer.has_sender() {
            println!(
                "{} Aborting operation: Raw Layer 2 packet injection sender is not initialized (Npcap unavailable).",
                "[ERR]".red().bold()
            );
            return;
        }

        // 3. Pre-validate target scope and exclusions
        let validator = self.admission_validator();
        let mut target_hosts = Vec::new();
        for id in ids {
            if let Some(host) = self.hosts.iter().find(|h| h.id == id).cloned() {
                if let Err(reason) = validator.validate_target(
                    &host.ip,
                    Some(&host.mac),
                    AdmissionOperation::LocalEnforcement,
                ) {
                    if args[0].eq_ignore_ascii_case("all") {
                        continue;
                    }
                    println!(
                        "{} Scope / Admission Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }
                target_hosts.push(host);
            }
        }

        if target_hosts.is_empty() {
            println!(
                "{} No valid in-scope target hosts to simulate.",
                "[WARN]".yellow().bold()
            );
            return;
        }

        // 4. Fail-closed forwarding check: Abort operation if forwarding cannot be enabled
        if let Err(e) = crate::platform::ensure_scoped_forwarding_enabled(&self.iface.name) {
            println!(
                "{} Aborting operation: Failed to enable scoped IP forwarding on {}: {}",
                "[ERR]".red().bold(),
                self.iface.name,
                e
            );
            return;
        }

        // 5. Atomic multi-target activation with transactional rollback
        let mut activated = Vec::new();
        let mut failure = None;
        for host in &target_hosts {
            match self.spoofer.add(host.clone()) {
                Ok(()) => {
                    self.limiter.set_fault(host.ip, profile.clone());
                    activated.push(host.clone());
                }
                Err(err) => {
                    failure = Some((host.ip, err));
                    break;
                }
            }
        }

        if let Some((failed_ip, err)) = failure {
            for act in &activated {
                self.spoofer.remove(&act.ip);
                self.limiter.clear_fault(&act.ip);
            }
            println!(
                "{} Simulation transaction failed on {}: {}. Rolled back {} previously activated target(s). Zero state mutated.",
                "[ERR]".red().bold(),
                failed_ip,
                err,
                activated.len()
            );
            return;
        }

        for host in target_hosts {
            println!(
                "{} Simulated network resilience profile on {}: drop={}% delay={}ms jitter={}ms",
                "OK".green().bold(),
                host.ip,
                drop_pct,
                delay_ms,
                jitter_ms
            );
        }
    }

    pub fn handle_export(&self, args: &[&str]) {
        if self.is_router_lab {
            println!(
                "{} Top-level export is disabled in router-lab mode. Use 'router export-evidence' instead.",
                "[ERR]".red().bold()
            );
            return;
        }

        let fmt = args
            .first()
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "markdown".to_string());
        let default_filename = match fmt.as_str() {
            "json" => "rustrict-assessment.json",
            "sarif" => "rustrict-assessment.sarif",
            _ => "rustrict-assessment.md",
        };
        let target_file = args.get(1).unwrap_or(&default_filename);

        let result = match fmt.as_str() {
            "json" => crate::cli::export::export_json(&self.scope, &self.services, &self.findings)
                .map_err(|e| e.to_string()),
            "sarif" => crate::cli::export::export_sarif(&self.findings).map_err(|e| e.to_string()),
            "markdown" | "md" => Ok(crate::cli::export::export_markdown(
                &self.scope,
                &self.services,
                &self.findings,
            )),
            _ => Ok(crate::cli::export::export_markdown(
                &self.scope,
                &self.services,
                &self.findings,
            )),
        };

        match result {
            Ok(content) => match crate::cli::export::save_report(target_file, &content) {
                Ok(_) => {
                    println!(
                        "{} Successfully exported assessment report to '{}' ({} bytes)",
                        "OK".green().bold(),
                        target_file,
                        content.len()
                    );
                }
                Err(e) => {
                    println!(
                        "{} Failed to write report to '{}': {}",
                        "[ERR]".red().bold(),
                        target_file,
                        e
                    );
                }
            },
            Err(e) => println!("{} Failed to generate export: {}", "[ERR]".red().bold(), e),
        }
    }

    fn resolve_targets(&self, arg: &str) -> Result<Vec<usize>, String> {
        resolve_targets(&self.hosts, arg)
    }

    fn print_help(&self) {
        if self.is_router_lab {
            println!(
                "{}",
                "rustrict Router-Lab Commands (READ-ONLY Mode):"
                    .bright_yellow()
                    .bold()
            );
            println!("  hosts                                           Displays inactive host inventory (local enforcement disabled)");
            println!("  nic [status|health|stats|list] [name|index]     Physical network adapter health telemetry and diagnostics (read-only)");
            println!("  router providers                                List all supported router administration providers");
            println!("  router connect <ssh|mikrotik|avm|unifi|http>    Connect to physical router provider using authenticated transport");
            println!("  router status                                   Display current router identity and connection status");
            println!("  router capabilities                             Inspect discovered router capabilities and evidence classification");
            println!("  router devices                                  List connected client devices discovered on router (read-only)");
            println!("  router diagnostics                              Run comprehensive read-only router diagnostic checks");
            println!("  router preview <all|id|ip> [options]            Dry-run preflight inspection of policy (read-only, no mutation)");
            println!("  router inventory                                Display router inventory");
            println!("  router policies                                 Display active and historical router policies");
            println!("  router policy <policy_id>                       Display detailed inspection of a specific policy");
            println!("  router history                                  Display persistent audit records of policy executions");
            println!("  router export-evidence [path] [--overwrite]     Export full sanitized read-only evidence bundle (JSON)");
            println!("  router validate-evidence <path>                 Validate exported evidence bundle offline");
            println!("  router disconnect                               Cleanly disconnect active provider (no fallback to ARP)");
            println!("  upgrade / update                                Instructions to upgrade rustrict to latest release");
            println!("  clear / cls                                     Clears screen");
            println!("  quit / exit                                     Exits rustrict cleanly\n");
            return;
        }

        println!("{}", "rustrict Commands:".bright_yellow().bold());
        println!("  scan [--range <start-end>] [--fresh] [--ports]  Scans network (use --ports for service enumeration)");
        println!("  hosts / devices / list                          Displays discovered hosts and live online/offline state");
        println!("  status                                          Displays complete runtime system, adapter, and network status");
        println!("  scope [status|add <cidr|all|local>|reset|clear] Manages authorized targets and operational boundaries");
        println!("  strict [off|on] / permissive                    Toggles strict CIDR boundary enforcement (permissive by default)");
        println!("  mode / blockmode [mitm|blackhole]               Sets block mode: 'mitm' (WinDivert kernel drop) or 'blackhole' (L2 drop)");
        println!("  ports <id|ip|all> [port-range]                  Enumerates open TCP services and grabs service banners");
        println!("  audit <id|ip|all>                               Performs active security posture checks (TLS & SMB)");
        println!("  simulate <id|ip|all> [drop %] [delay ms] [...]  Simulates network resilience and fault injection");
        println!("  export [markdown|json|sarif] [filename]         Exports structured assessment reports and evidence");
        println!("  limit <id|ip|all> <rate> [...]                  Limits bandwidth (e.g. limit 1 200kbit, limit all 1mbit)");
        println!("  block <id|ip|all> [...]                         Blocks host internet access [Persists across restarts]");
        println!("  free / unblock <id|ip|all>                      Removes limits and unblocks host [Clears persistent rule]");
        println!("  state [status|clear]                            Inspects or clears persistent blocked records and saved state");
        println!("  add <ip> [--mac <mac>]                          Manually adds a host to table");
        println!("  router [capabilities|status|policies|preview|pause|resume|adjust|connect] [...] Router administration via authenticated firewall");
        println!("  nic [status|health|stats|list] [name|index]     Physical network adapter health telemetry and diagnostics");
        println!("  upgrade / update                                Instructions to upgrade rustrict to latest release");
        println!("  clear                                           Clears screen");
        println!("  quit / exit                                     Exits rustrict and restores network\n");
    }

    pub fn scope_mut(&mut self) -> &mut ScopeManager {
        &mut self.scope
    }

    pub fn set_strict_mode(&mut self, strict: bool) {
        self.scope.set_strict(strict);
    }

    pub fn set_spoofer_mode(&mut self, mode: crate::spoofer::SpooferMode) {
        self.spoofer.set_mode(mode);
    }

    fn handle_blockmode(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!(
                "Current block enforcement mode: {}",
                match self.spoofer.mode() {
                    crate::spoofer::SpooferMode::Blackhole =>
                        "BLACKHOLE (L2 blackhole MAC 02:bf:00:00:00:01, zero local NIC load)"
                            .bright_green()
                            .bold(),
                    crate::spoofer::SpooferMode::Mitm =>
                        "MITM (Routed to local host MAC, dropped in WinDivert kernel filter)"
                            .bright_cyan()
                            .bold(),
                }
            );
            println!("  Usage: 'blockmode blackhole' (drop at L2 switch/AP) or 'blockmode mitm' (drop via WinDivert kernel driver)");
            return;
        }

        match args[0].to_lowercase().as_str() {
            "blackhole" | "bh" | "l2" => {
                self.spoofer
                    .set_mode(crate::spoofer::SpooferMode::Blackhole);
                println!(
                    "{} Spoofer block mode switched to: {}",
                    "OK".green().bold(),
                    "BLACKHOLE (02:bf:00:00:00:01 - dropped silently at L2)"
                        .bright_green()
                        .bold()
                );
            }
            "mitm" | "divert" | "drop" | "kernel" => {
                self.spoofer.set_mode(crate::spoofer::SpooferMode::Mitm);
                println!(
                    "{} Spoofer block mode switched to: {}",
                    "OK".green().bold(),
                    "MITM (Routed to local host and dropped by WinDivert kernel filter)"
                        .bright_cyan()
                        .bold()
                );
            }
            other => {
                println!(
                    "{} Unknown block mode '{}'. Choose 'blackhole' or 'mitm'.",
                    "[ERR]".bright_red().bold(),
                    other
                );
            }
        }
    }

    pub fn handle_upgrade(&self) {
        println!(
            "\n{}",
            "─── Rustrict Update & Upgrade Guide ───".cyan().bold()
        );
        println!("Official Repository: https://github.com/Neutron-0/Rustrict");
        println!("\nTo install or update Rustrict at any time, run in PowerShell:");
        println!("  {}", "irm https://raw.githubusercontent.com/Neutron-0/Rustrict/main/scripts/install.ps1 | iex".yellow().bold());
        println!("\nPersistence & Driver Invariants:");
        println!("  • Persisted block rules and scope settings in %ProgramData%\\Rustrict are safely preserved.");
        println!(
            "  • Kernel driver services (WinDivert) are safely retained without interruption.\n"
        );
    }

    pub fn handle_nic(&self, args: &[&str]) {
        use crate::monitor::nic::{run_nic_cli, WindowsPowershellNicProvider};

        let provider = WindowsPowershellNicProvider::default();
        if let Err(e) = run_nic_cli(&provider, Some(self.iface.name.as_str()), args) {
            eprintln!(
                "{} NIC health diagnostic failed: {}",
                "[ERR]".bright_red().bold(),
                e
            );
        }
    }

    pub fn handle_router(&mut self, args: &[&str]) {
        if args.is_empty() || args[0].eq_ignore_ascii_case("help") {
            if self.is_router_lab {
                println!(
                    "{}",
                    "Router Administrative Commands (READ-ONLY Router-Lab Mode):"
                        .bright_yellow()
                        .bold()
                );
                println!("  router providers                                List all supported router administration providers");
                println!("  router capabilities                             Inspect discovered router capabilities and evidence classification");
                println!("  router status                                   Display current router identity and connection status");
                println!("  router diagnostics / router diag                Run comprehensive read-only diagnostic checks without mutating rules");
                println!("  router devices / router clients                 List connected client devices discovered on router (read-only)");
                println!("  router export-evidence [path] [--overwrite]     Export full sanitized read-only evidence bundle (JSON)");
                println!("  router validate-evidence <path>                 Validate exported evidence bundle offline");
                println!("  router inventory                                Normalized provider inventory with live vs cached router identity");
                println!("  router policies [policy_id]                     Display unified router policies or inspect specific policy");
                println!("  router policy <policy_id>                       Display detailed inspection and event timeline of a policy");
                println!("  router history / router records                 Display persistent audit records of policy executions on Windows");
                println!("  router preview <all|id|ip> [options]            Dry-run preview of an administrative policy without executing it");
                println!("  router connect <provider> [endpoint] [options]  Connect to a physical router provider explicitly");
                println!("  router disconnect                               Cleanly disconnect active provider (no fallback to ARP poisoning)");
                println!();
                println!("{}", "  Prohibited in router-lab mode:".bright_red().bold());
                println!("    router pause, router resume, router adjust, router refresh, router connect mock\n");
                return;
            }

            println!(
                "{}",
                "Router Administrative Commands:".bright_yellow().bold()
            );
            println!("  router inventory                                Normalized provider inventory with live vs cached router identity");
            println!("  router providers                                List all supported router administration providers and capabilities");
            println!("  router capabilities                             Inspect discovered router capabilities and evidence classification");
            println!("  router status                                   Display current router identity and connection status");
            println!("  router diagnostics / router diag                Run comprehensive read-only diagnostic checks without mutating rules");
            println!("  router export-evidence [path] [--overwrite]     Export full sanitized read-only evidence bundle (JSON)");
            println!("  router validate-evidence <path>                 Validate exported evidence bundle offline");
            println!("  router devices / router clients                 List connected client devices discovered on router (where supported)");
            println!("  router policies [policy_id]                     Display unified router policies or inspect specific policy");
            println!("  router policy <policy_id>                       Display detailed inspection and event timeline of a policy");
            println!("  router refresh / router reconcile               Safely verify active router policies without mutating router rules");
            println!("  router history / router records                 Display persistent audit records of policy executions on Windows");
            println!("  router preview <all|id|ip> [options]            Dry-run preview of an administrative policy without executing it");
            println!("  router pause <all|id|ip> [options] [--yes]      Enforce an internet pause on the router (requires auth)");
            println!("  router resume <all|id|ip> [--yes]               Revoke router-enforced pause and resume internet access");
            println!("  router adjust <all|id|ip> --duration <s|indef> [--yes] Extend or shorten an existing policy's expiration");
            println!("  router connect <provider> [endpoint] [options]  Connect to a router provider explicitly");
            println!("  router disconnect                               Cleanly disconnect active provider (no fallback to ARP poisoning)");
            println!("  router connect http [endpoint] [--user <user>]  Connect to OpenWrt via authenticated HTTP JSON-RPC");
            println!("  router connect ssh [host] [options]             Connect to OpenWrt via authenticated SSH");
            println!("  router connect mikrotik [endpoint] [options]    Connect to MikroTik RouterOS via HTTPS REST API");
            println!("  router connect avm [endpoint] [options]         Connect to AVM FRITZ!Box via TR-064 SOAP API");
            println!("  router connect unifi [endpoint] [options]       Connect to Ubiquiti UniFi Controller via HTTPS REST API");
            println!("  router connect mock                             Connect to in-memory Mock Router Provider");
            println!("    UniFi Options:");
            println!("      --site <site-id>       UniFi site identifier (default: default)");
            println!("      --user <username>      UniFi username or \"api-key\" (default: admin)");
            println!(
                "      --ca-cert <path>       Custom CA certificate path for TLS verification"
            );
            println!("    AVM Options:");
            println!("      --user <username>      FRITZ!Box username (default: admin)");
            println!(
                "      --ca-cert <path>       Custom CA certificate path for TLS verification"
            );
            println!("    MikroTik Options:");
            println!("      --user <username>      RouterOS username (default: admin)");
            println!(
                "      --ca-cert <path>       Custom CA certificate path for TLS verification"
            );
            println!("    SSH Options:");
            println!("      --port <port>          SSH port (default: 22)");
            println!("      --user <username>      SSH username (default: root)");
            println!(
                "      --key <key_path>       Path to SSH private key (e.g. ~/.ssh/id_ed25519)"
            );
            println!("      --pin <host_key>       Pin expected host public key / fingerprint");
            println!("    Policy Options:");
            println!("      --duration <seconds>   Temporary duration with autonomous router-side expiry (e.g. --duration 300)");
            println!("      --persistent           Configure policy to persist on router across reboots/disconnects");
            return;
        }

        match args[0].to_lowercase().as_str() {
            "inventory" => {
                let inventory = self.policy_engine.get_inventory();
                render_router_inventory_table(&inventory);
            }
            "providers" => {
                let providers = self.router_registry.list_providers();
                let active_id = self.router_registry.active_provider_id();
                render_router_providers_table(&providers, active_id.as_deref());
            }
            "disconnect" => {
                if self.router_registry.is_connected() {
                    let prev_id = self
                        .router_registry
                        .active_provider_id()
                        .unwrap_or_default();
                    self.router_registry.disconnect();
                    self.admin_provider =
                        self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                    println!("{} Disconnected router provider '{}'. Subsystem cleanly disconnected without fallback to ARP poisoning.", "[INFO]".cyan().bold(), prev_id);
                } else {
                    println!(
                        "{} No router provider currently connected.",
                        "[INFO]".cyan().bold()
                    );
                }
            }
            "capabilities" | "caps" => {
                let caps = self.admin_provider.inspect_capabilities();
                render_router_capabilities_table(&caps);
            }
            "status" => {
                let reg_status = self.router_registry.get_status();
                if !reg_status.is_connected {
                    println!(
                        "{}",
                        "Router Identity & Administration Status:"
                            .bright_yellow()
                            .bold()
                    );
                    println!("  • Status:         {}", "DISCONNECTED".red().bold());
                    println!("  • Connection:     No router provider is currently connected");
                    println!("  • Available:      Use 'router inventory' or 'router providers' to view options, and 'router connect <provider>' to connect.");
                    if let Some(err) = self.policy_engine.last_persistence_error() {
                        println!(
                            "  • Persistence Alert: {}",
                            format!("DISK WRITE FAILED: {}", err).red().bold()
                        );
                    }
                    return;
                }
                match self.admin_provider.detect_identity() {
                    Ok(id) => {
                        println!(
                            "{}",
                            "Router Identity & Administration Status:"
                                .bright_yellow()
                                .bold()
                        );
                        println!(
                            "  • Provider:       {}",
                            self.admin_provider.name().bright_cyan()
                        );
                        if let Some(id_str) = self.router_registry.active_provider_id() {
                            println!("  • Provider ID:    {}", id_str.bright_cyan());
                        }
                        if let Some(ep) = &reg_status.endpoint {
                            println!(
                                "  • Endpoint:       {}",
                                crate::gateway::admin::sanitize_endpoint(ep).bright_white()
                            );
                        }
                        println!("  • Router:         {}", id.display_summary());
                        if reg_status.provider_id.as_deref() == Some("mock") {
                            println!(
                                "  • Mode:           {}",
                                "[SIMULATED / TEST MODE] (In-memory mock router; no physical hardware modified)"
                                    .bright_yellow()
                                    .bold()
                            );
                        }
                        println!(
                            "  • Authenticated:  {}",
                            if self.admin_provider.is_authenticated() {
                                "YES".green().bold()
                            } else {
                                "NO".red().bold()
                            }
                        );
                        if let Some(contact) = reg_status.last_contact_unix {
                            println!("  • Last Contact:   Unix timestamp {} (LIVE)", contact);
                        }
                        println!(
                            "  • Enforcement:    Router-Side Forwarding Rejection (Hardware L3/L4)"
                        );
                        println!(
                            "  • Management:     Router administration & intra-LAN preserved 100%"
                        );
                        if let Some(err) = self.policy_engine.last_persistence_error() {
                            println!(
                                "  • Persistence Alert: {}",
                                format!("DISK WRITE FAILED: {}", err).red().bold()
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to query router identity: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "diagnostics" | "diag" => {
                println!(
                    "{} Executing read-only router diagnostic checks...",
                    "[INFO]".cyan().bold()
                );
                let report = self.policy_engine.run_diagnostics();
                render_router_diagnostics_report(&report);
            }
            "export-evidence" | "export" => {
                let mut path = None;
                let mut overwrite = false;
                let mut idx = 1;
                while idx < args.len() {
                    match args[idx].to_lowercase().as_str() {
                        "--overwrite" | "-f" => {
                            overwrite = true;
                            idx += 1;
                        }
                        other if !other.starts_with('-') && path.is_none() => {
                            path = Some(std::path::PathBuf::from(args[idx]));
                            idx += 1;
                        }
                        _ => {
                            idx += 1;
                        }
                    }
                }

                let target_path = path.unwrap_or_else(|| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    std::path::PathBuf::from(format!("rustrict-evidence-{}.json", now))
                });

                println!(
                    "{} Generating sanitized read-only diagnostic evidence bundle...",
                    "[EXEC]".cyan().bold()
                );

                match self
                    .policy_engine
                    .export_evidence_bundle(&target_path, overwrite)
                {
                    Ok(bundle) => {
                        let size = std::fs::metadata(&target_path)
                            .map(|m| m.len())
                            .unwrap_or_default();
                        println!(
                            "{} Diagnostic evidence bundle successfully exported to: {}",
                            "[SUCCESS]".green().bold(),
                            target_path.display().to_string().bright_yellow()
                        );
                        println!("  • File Size:      {} bytes", size);
                        println!("  • Timestamp:      {}", bundle.generated_at_iso8601);
                        println!(
                            "  • Provider:       {} ({})",
                            bundle.provider_name, bundle.provider_id
                        );
                        let identity_str = bundle
                            .router_identity
                            .as_ref()
                            .map(|id| id.display_summary())
                            .unwrap_or_else(|| "Unknown / Disconnected".into());
                        println!("  • Router:         {}", identity_str);
                        println!("  • Active Policies: {}", bundle.active_policies.len());
                        println!("  • Devices:        {}", bundle.device_inventory.len());
                        println!("  • Sanitization:   All credentials and session tokens strictly redacted");
                        println!(
                            "  • Safety:         Zero router configuration mutations performed"
                        );
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to export evidence bundle: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "validate-evidence" | "validate" => {
                if args.len() < 2 {
                    println!("Usage: router validate-evidence <path-to-json-bundle>");
                    return;
                }
                let bundle_path = std::path::Path::new(args[1]);
                match PolicyExecutionEngine::validate_evidence_file(bundle_path) {
                    Ok(report) => {
                        if report.valid {
                            println!(
                                "{} Evidence Bundle is VALID: {}",
                                "[VALID]".green().bold(),
                                bundle_path.display()
                            );
                        } else {
                            println!(
                                "{} Evidence Bundle has ISSUES: {}",
                                "[INVALID]".red().bold(),
                                bundle_path.display()
                            );
                        }
                        println!("  • Schema Version:      {}", report.schema_version);
                        println!("  • Generated (UTC):     {}", report.generated_at_iso8601);
                        println!("  • Provider ID:         {}", report.provider_id);
                        println!("  • Provider Name:       {}", report.provider_name);
                        if let Some(ep) = &report.endpoint {
                            println!("  • Endpoint:            {}", ep);
                        }
                        if let Some(id) = &report.router_identity {
                            println!("  • Router Identity:     {}", id);
                        }
                        println!("  • Active Policies:     {}", report.active_policy_count);
                        println!(
                            "  • Historical Policies: {}",
                            report.historical_policy_count
                        );
                        println!("  • Execution Records:   {}", report.execution_record_count);
                        println!("  • Device Inventory:    {}", report.device_count);

                        for issue in &report.issues {
                            println!("  • {} {}", "[ISSUE]".red().bold(), issue);
                        }
                        for warning in &report.warnings {
                            println!("  • {} {}", "[WARN]".yellow().bold(), warning);
                        }
                    }
                    Err(e) => {
                        println!("{} Evidence validation failed: {}", "[ERR]".red().bold(), e);
                    }
                }
            }
            "devices" | "clients" => {
                let reg_status = self.router_registry.get_status();
                let active_id = self.router_registry.active_provider_id();

                if !reg_status.is_connected {
                    println!(
                        "{}",
                        "Router Connected Client Device Inventory:"
                            .bright_yellow()
                            .bold()
                    );
                    println!("  • Connection Status: {}", "DISCONNECTED".red().bold());
                    println!("  • Selected Provider: None");
                    println!(
                        "  • Query Mode:        Unavailable (Live router connection required)"
                    );
                    println!();
                    println!(
                        "{} No router provider is currently connected. Establish a connection first with 'router connect <provider>'.",
                        "[INFO]".cyan().bold()
                    );

                    if !self.hosts.is_empty() {
                        println!(
                            "{} Displaying {} host(s) discovered via local PC passive ARP/subnet scanning (NOT router-verified):",
                            "[LOCAL PC SCAN]".yellow().bold(),
                            self.hosts.len()
                        );
                        render_hosts_table(&self.hosts);
                        println!(
                            "{} Note: The devices above reflect controller PC scan data, NOT router-enforced client leases.",
                            "[NOTE]".cyan().bold()
                        );
                    }
                    return;
                }

                let pid = active_id.unwrap_or_else(|| "unknown".into());
                let provider_name = self.admin_provider.name();
                println!(
                    "{}",
                    "Router Connected Client Device Inventory:"
                        .bright_yellow()
                        .bold()
                );
                println!(
                    "  • Selected Provider: {} ({})",
                    provider_name.bright_cyan(),
                    pid.bright_cyan()
                );
                if let Some(ep) = &reg_status.endpoint {
                    println!(
                        "  • Management Endpoint: {}",
                        crate::gateway::admin::sanitize_endpoint(ep).bright_white()
                    );
                }
                println!("  • Query Mode:        Live Router Inventory (Read-Only)");
                println!();

                match self.policy_engine.list_devices() {
                    Ok(devices) => {
                        if devices.is_empty() {
                            println!(
                                "{} No connected devices returned by provider '{}' (inventory is currently empty).",
                                "[INFO]".cyan().bold(),
                                pid
                            );
                        } else {
                            render_router_devices_table(&devices);
                        }
                    }
                    Err(crate::gateway::admin::AdminError::UnsupportedOperation(msg)) => {
                        println!(
                            "{} Client device inventory unsupported on provider '{}': {}",
                            "[INFO]".yellow().bold(),
                            pid,
                            msg
                        );
                        println!(
                            "  (Device inventory is supported on UniFi Network REST and AVM FRITZ!Box TR-064)"
                        );
                        println!(
                            "  (OpenWrt and MikroTik RouterOS do not currently support client device inventory via this transport)"
                        );
                    }
                    Err(e) => {
                        let sanitized = crate::gateway::admin::sanitize_error(e);
                        println!(
                            "{} Failed to query router devices: {}",
                            "[ERR]".red().bold(),
                            sanitized
                        );
                    }
                }
            }
            "policy" => {
                if args.len() < 2 {
                    println!("Usage: router policy <policy_id>");
                    return;
                }
                self.show_policy_detail(args[1]);
            }
            "policies" => {
                if let Some(err) = self.policy_engine.last_persistence_error() {
                    println!(
                        "{} Persistence alert: Policy state could not be persisted to disk: {}",
                        "[ALERT]".yellow().bold(),
                        err
                    );
                }
                if args.len() > 1 && !args[1].is_empty() {
                    self.show_policy_detail(args[1]);
                } else {
                    let unified = self.policy_engine.list_unified_policies();
                    render_router_unified_policies_table(&unified);
                }
            }
            "history" | "records" => {
                let records = self.policy_engine.store().records();
                render_router_history_table(&records);
            }
            "refresh" | "reconcile" => {
                if self.is_router_lab {
                    println!(
                        "{} Router policy reconciliation ('router refresh') is prohibited in router-lab mode.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                if !self.router_registry.is_connected() {
                    println!(
                        "{} No router provider currently connected. Querying live router rules requires an active provider connection.",
                        "[INFO]".cyan().bold()
                    );
                    println!(
                        "{} Displaying persistent historical state (unverified local state marked UNKNOWN until verified):",
                        "[LOCAL STATE]".yellow().bold()
                    );
                    let hist = self.policy_engine.store().historical_policies();
                    render_router_policies_table(&hist);
                    return;
                }

                if !self.admin_provider.is_authenticated() {
                    println!(
                        "{} Router provider is connected but not authenticated. Run 'router connect' with credentials to authenticate.",
                        "[WARN]".yellow().bold()
                    );
                    let hist = self.policy_engine.store().historical_policies();
                    render_router_policies_table(&hist);
                    return;
                }

                println!(
                    "{} Querying live router firewall rules via {} (read-only verification)...",
                    "[INFO]".cyan().bold(),
                    self.admin_provider.name()
                );

                match self.admin_provider.reconcile_policies() {
                    Ok(policies) => {
                        println!(
                            "{} Successfully refreshed router state! Discovered {} verified live policy rule(s).",
                            "[SUCCESS]".green().bold(),
                            policies.len()
                        );
                        render_router_policies_table(&policies);
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to query live router rules: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "preview" => {
                if args.len() < 2 {
                    println!(
                        "Usage: router preview <all|id|ip> [--duration <secs>] [--persistent]"
                    );
                    return;
                }

                let target_arg = args[1];
                let mut duration = PolicyDuration::Indefinite;
                let mut persistence = PolicyPersistence::VolatileSession;

                let mut idx = 2;
                while idx < args.len() {
                    match args[idx].to_lowercase().as_str() {
                        "--duration" | "-d" => {
                            if idx + 1 < args.len() {
                                if let Ok(secs) = args[idx + 1].parse::<u64>() {
                                    if secs == 0 {
                                        println!(
                                            "{} Duration must be a positive number of seconds.",
                                            "[ERR]".red().bold()
                                        );
                                        return;
                                    }
                                    duration = PolicyDuration::Temporary(
                                        std::time::Duration::from_secs(secs),
                                    );
                                    idx += 2;
                                    continue;
                                }
                            }
                            println!(
                                "{} Invalid or missing duration seconds. Example: --duration 300",
                                "[ERR]".red().bold()
                            );
                            return;
                        }
                        "--persistent" | "-p" => {
                            persistence = PolicyPersistence::RouterPersistent;
                            idx += 1;
                        }
                        _ => {
                            println!(
                                "{} Unknown option '{}'",
                                "[WARN]".yellow().bold(),
                                args[idx]
                            );
                            idx += 1;
                        }
                    }
                }

                let (scope, target_macs) = if target_arg.eq_ignore_ascii_case("all") {
                    (PolicyScope::NetworkWide, Vec::new())
                } else {
                    match self.resolve_single_target(target_arg) {
                        Ok((ip, mac)) => {
                            if let Err(e) = self.admission_validator().validate_target(
                                &ip,
                                mac.as_ref(),
                                AdmissionOperation::RouterPolicy,
                            ) {
                                println!(
                                    "{} Target {} is blocked by operational scope: {}",
                                    "[ERR]".red().bold(),
                                    ip,
                                    e
                                );
                                return;
                            }
                            let macs = mac.into_iter().collect();
                            (PolicyScope::SpecificTargets(vec![ip]), macs)
                        }
                        Err(e) => {
                            println!("{} {}", "[ERR]".red().bold(), e);
                            return;
                        }
                    }
                };

                let req = OperationPlanRequest {
                    scope,
                    duration,
                    persistence,
                    target_macs,
                };

                match self.admin_provider.plan_operation(&req) {
                    Ok(plan) => {
                        render_router_plan_preview(&plan);
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to plan router operation: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "pause" => {
                if self.is_router_lab {
                    println!(
                        "{} Router policy enforcement ('router pause') is prohibited in router-lab mode.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                if args.len() < 2 {
                    println!("Usage: router pause <all|id|ip> [--duration <secs>] [--persistent] [--yes]");
                    return;
                }

                if !self.admin_provider.is_authenticated() {
                    println!(
                        "{} Router administrative provider is not authenticated. Configure credentials or run 'router connect' first.",
                        "[ERR]".red().bold()
                    );
                    println!(
                        "{} Refusing to execute: will NOT silently fall back to ARP spoofing.",
                        "[SECURITY]".yellow().bold()
                    );
                    return;
                }

                let target_arg = args[1];
                let is_all = target_arg.eq_ignore_ascii_case("all");

                let mut duration = PolicyDuration::Indefinite;
                let mut persistence = PolicyPersistence::VolatileSession;
                let mut auto_confirm = false;

                let mut idx = 2;
                while idx < args.len() {
                    match args[idx].to_lowercase().as_str() {
                        "--duration" | "-d" => {
                            if idx + 1 < args.len() {
                                if let Ok(secs) = args[idx + 1].parse::<u64>() {
                                    if secs == 0 {
                                        println!(
                                            "{} Duration must be a positive number of seconds.",
                                            "[ERR]".red().bold()
                                        );
                                        return;
                                    }
                                    duration = PolicyDuration::Temporary(
                                        std::time::Duration::from_secs(secs),
                                    );
                                    idx += 2;
                                    continue;
                                }
                            }
                            println!(
                                "{} Invalid or missing duration seconds. Example: --duration 300",
                                "[ERR]".red().bold()
                            );
                            return;
                        }
                        "--persistent" | "-p" => {
                            persistence = PolicyPersistence::RouterPersistent;
                            idx += 1;
                        }
                        "--yes" | "-y" => {
                            auto_confirm = true;
                            idx += 1;
                        }
                        _ => {
                            println!(
                                "{} Unknown option '{}'",
                                "[WARN]".yellow().bold(),
                                args[idx]
                            );
                            idx += 1;
                        }
                    }
                }

                let (scope, target_macs) = if is_all {
                    (PolicyScope::NetworkWide, Vec::new())
                } else {
                    match self.resolve_single_target(target_arg) {
                        Ok((ip, mac)) => {
                            if let Err(e) = self.admission_validator().validate_target(
                                &ip,
                                mac.as_ref(),
                                AdmissionOperation::RouterPolicy,
                            ) {
                                println!(
                                    "{} Target {} is blocked by operational scope: {}",
                                    "[ERR]".red().bold(),
                                    ip,
                                    e
                                );
                                return;
                            }
                            let macs = mac.into_iter().collect();
                            (PolicyScope::SpecificTargets(vec![ip]), macs)
                        }
                        Err(e) => {
                            println!("{} {}", "[ERR]".red().bold(), e);
                            return;
                        }
                    }
                };

                let req = OperationPlanRequest {
                    scope,
                    duration,
                    persistence,
                    target_macs,
                };

                let plan = match self.policy_engine.plan_policy(&req) {
                    Ok(p) => p,
                    Err(e) => {
                        println!(
                            "{} Preflight validation failed: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                        return;
                    }
                };

                println!(
                    "{} Preflight Inspection for Router Firewall Mutation:",
                    "[PREFLIGHT]".cyan().bold()
                );
                println!("  • Provider:       {}", plan.provider_name);
                println!(
                    "  • Router Identity: {}",
                    plan.router_identity.display_summary()
                );
                println!(
                    "  • Scope:          {} (Target Count: {})",
                    plan.target_scope, plan.target_count
                );
                println!("  • Duration:       {}", plan.duration);
                println!("  • Persistence:    {}", plan.persistence);
                println!("  • Recovery:       {}", plan.recovery_mechanism);

                for risk in &plan.uncertainties_and_risks {
                    println!("  • {} {}", "[RISK/WARNING]".yellow().bold(), risk);
                }

                let is_mock = self.router_registry.active_provider_id().as_deref() == Some("mock");
                if is_mock {
                    println!(
                        "  • Notice:         {}",
                        "[SIMULATED] Mock router test mode active — no physical hardware will be modified."
                            .bright_yellow()
                            .bold()
                    );
                } else if !auto_confirm {
                    let prompt_text = if is_all {
                        "WARNING: You are requesting to pause internet transit for ALL network devices.\nConfirm network-wide router enforcement? [yes/N]: "
                    } else {
                        "Confirm policy enforcement on physical router? [yes/N]: "
                    };
                    print!(
                        "{} {}",
                        "[CONFIRMATION REQUIRED]".bright_red().bold(),
                        prompt_text
                    );
                    let _ = io::stdout().flush();
                    let confirm = self.read_confirmation_input().unwrap_or_default();
                    if !matches!(confirm.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
                        println!(
                            "{} Policy enforcement cancelled by administrator. Zero router mutations performed.",
                            "[INFO]".cyan().bold()
                        );
                        return;
                    }
                }

                println!(
                    "{} Applying policy via router firewall provider: {} (Enforcement: Router-side transit rejection)",
                    "[EXEC]".cyan().bold(),
                    self.admin_provider.name()
                );

                match self.admin_provider.apply_policy(&req) {
                    Ok(active) => {
                        println!(
                            "{} Policy successfully applied by router! Policy ID: {}",
                            "[SUCCESS]".green().bold(),
                            active.policy_id.bright_yellow()
                        );
                        if self.router_registry.active_provider_id().as_deref() == Some("mock") {
                            println!(
                                "  • Notice:         {}",
                                "[SIMULATED] Mock router test mode - no physical hardware changed."
                                    .bright_yellow()
                                    .bold()
                            );
                        }
                        if let Some(exp) = active.expires_at_unix {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let remaining = exp.saturating_sub(now);
                            println!(
                                "  • Expiration: {:.1} minutes remaining (Unix timestamp: {})",
                                remaining as f64 / 60.0,
                                exp
                            );
                        } else {
                            println!("  • Duration: Indefinite (manual 'router resume' required)");
                        }
                        println!(
                            "  • Persistence: {}",
                            if active.is_persistent {
                                "Committed to Router Storage"
                            } else {
                                "Volatile Session"
                            }
                        );
                        println!("  • Intra-LAN traffic & router administration port 80/443 remain 100% accessible.");
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to apply router policy: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                        println!(
                            "{} Refusing to fall back to ARP poisoning.",
                            "[SECURITY]".yellow().bold()
                        );
                    }
                }
            }
            "resume" => {
                if self.is_router_lab {
                    println!(
                        "{} Router policy revocation ('router resume') is prohibited in router-lab mode.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                if args.len() < 2 {
                    println!("Usage: router resume <all|id|ip> [--yes]");
                    return;
                }

                if !self.admin_provider.is_authenticated() {
                    println!(
                        "{} Router administrative provider is not authenticated.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                let target_arg = args[1];
                let is_all = target_arg.eq_ignore_ascii_case("all");

                let mut auto_confirm = false;
                let mut idx = 2;
                while idx < args.len() {
                    match args[idx].to_lowercase().as_str() {
                        "--yes" | "-y" => {
                            auto_confirm = true;
                            idx += 1;
                        }
                        _ => {
                            idx += 1;
                        }
                    }
                }

                let scope = if is_all {
                    PolicyScope::NetworkWide
                } else if target_arg.starts_with("pol-")
                    || self
                        .policy_engine
                        .store()
                        .historical_policies()
                        .iter()
                        .any(|p| p.policy_id == target_arg)
                {
                    if let Some(pol) = self
                        .policy_engine
                        .store()
                        .historical_policies()
                        .iter()
                        .find(|p| p.policy_id == target_arg)
                    {
                        pol.scope.clone()
                    } else {
                        println!(
                            "{} Policy ID '{}' not found in recorded policies.",
                            "[ERR]".red().bold(),
                            target_arg
                        );
                        return;
                    }
                } else {
                    match self.resolve_single_target(target_arg) {
                        Ok((ip, _mac)) => PolicyScope::SpecificTargets(vec![ip]),
                        Err(e) => {
                            println!("{} {}", "[ERR]".red().bold(), e);
                            return;
                        }
                    }
                };

                let unreconciled = self.policy_engine.check_unreconciled_failures();
                if !unreconciled.is_empty() {
                    println!(
                        "{} Prior unresolved partial failure or ambiguous router state detected:",
                        "[RISK/WARNING]".yellow().bold()
                    );
                    for w in &unreconciled {
                        println!("  • {}", w);
                    }
                }

                println!(
                    "{} Preflight Inspection for Router Policy Revocation:",
                    "[PREFLIGHT]".cyan().bold()
                );
                println!("  • Provider:       {}", self.admin_provider.name());
                let router_summary = self
                    .router_registry
                    .get_status()
                    .verified_identity
                    .map(|id| id.display_summary())
                    .unwrap_or_else(|| "Unknown Router".to_string());
                println!("  • Router Identity: {}", router_summary);
                println!("  • Scope:          {}", scope);
                println!("  • Action:         Revoke router transit drop rules (restore internet access)");

                let is_mock = self.router_registry.active_provider_id().as_deref() == Some("mock");
                if is_mock {
                    println!(
                        "  • Notice:         {}",
                        "[SIMULATED] Mock router test mode active — no physical hardware will be modified."
                            .bright_yellow()
                            .bold()
                    );
                } else if !auto_confirm {
                    print!(
                        "{} Confirm policy revocation on physical router? [yes/N]: ",
                        "[CONFIRMATION REQUIRED]".bright_red().bold()
                    );
                    let _ = io::stdout().flush();
                    let confirm = self.read_confirmation_input().unwrap_or_default();
                    if !matches!(confirm.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
                        println!(
                            "{} Policy revocation cancelled by administrator. Zero router mutations performed.",
                            "[INFO]".cyan().bold()
                        );
                        return;
                    }
                }

                println!(
                    "{} Revoking router policy rules via {}...",
                    "[EXEC]".cyan().bold(),
                    self.admin_provider.name()
                );

                match if is_all {
                    self.admin_provider.resume_all()
                } else {
                    self.admin_provider.resume_policy(&scope)
                } {
                    Ok(resumed) => {
                        println!(
                            "{} Successfully resumed internet access! Removed {} policy rule(s): {:?}",
                            "[SUCCESS]".green().bold(),
                            resumed.len(),
                            resumed
                        );
                        if self.router_registry.active_provider_id().as_deref() == Some("mock") {
                            println!(
                                "  • Notice:         {}",
                                "[SIMULATED] Mock router test mode - no physical hardware changed."
                                    .bright_yellow()
                                    .bold()
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to resume router policy: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "adjust" => {
                if self.is_router_lab {
                    println!(
                        "{} Router policy adjustment ('router adjust') is prohibited in router-lab mode.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                if args.len() < 2 {
                    println!("Usage: router adjust <all|id|ip> --duration <secs> [--yes]");
                    return;
                }

                if !self.admin_provider.is_authenticated() {
                    println!(
                        "{} Router administrative provider is not authenticated.",
                        "[ERR]".red().bold()
                    );
                    return;
                }

                let target_arg = args[1];
                let is_all = target_arg.eq_ignore_ascii_case("all");

                let mut duration = None;
                let mut auto_confirm = false;
                let mut idx = 2;
                while idx < args.len() {
                    match args[idx].to_lowercase().as_str() {
                        "--duration" | "-d" => {
                            if idx + 1 < args.len() {
                                if let Ok(secs) = args[idx + 1].parse::<u64>() {
                                    if secs > 0 {
                                        duration = Some(PolicyDuration::Temporary(
                                            std::time::Duration::from_secs(secs),
                                        ));
                                        idx += 2;
                                        continue;
                                    }
                                }
                            }
                            println!(
                                "{} Invalid duration seconds. Example: --duration 600",
                                "[ERR]".red().bold()
                            );
                            return;
                        }
                        "--indefinite" => {
                            duration = Some(PolicyDuration::Indefinite);
                            idx += 1;
                        }
                        "--yes" | "-y" => {
                            auto_confirm = true;
                            idx += 1;
                        }
                        _ => {
                            idx += 1;
                        }
                    }
                }

                let new_duration = match duration {
                    Some(d) => d,
                    None => {
                        println!("Usage: router adjust <all|id|ip> --duration <secs> [--yes]");
                        return;
                    }
                };

                let scope = if is_all {
                    PolicyScope::NetworkWide
                } else if target_arg.starts_with("pol-")
                    || self
                        .policy_engine
                        .store()
                        .historical_policies()
                        .iter()
                        .any(|p| p.policy_id == target_arg)
                {
                    if let Some(pol) = self
                        .policy_engine
                        .store()
                        .historical_policies()
                        .iter()
                        .find(|p| p.policy_id == target_arg)
                    {
                        pol.scope.clone()
                    } else {
                        println!(
                            "{} Policy ID '{}' not found in recorded policies.",
                            "[ERR]".red().bold(),
                            target_arg
                        );
                        return;
                    }
                } else {
                    match self.resolve_single_target(target_arg) {
                        Ok((ip, _mac)) => PolicyScope::SpecificTargets(vec![ip]),
                        Err(e) => {
                            println!("{} {}", "[ERR]".red().bold(), e);
                            return;
                        }
                    }
                };

                let unreconciled = self.policy_engine.check_unreconciled_failures();
                if !unreconciled.is_empty() {
                    println!(
                        "{} Prior unresolved partial failure or ambiguous router state detected:",
                        "[RISK/WARNING]".yellow().bold()
                    );
                    for w in &unreconciled {
                        println!("  • {}", w);
                    }
                }

                println!(
                    "{} Preflight Inspection for Router Policy Adjustment:",
                    "[PREFLIGHT]".cyan().bold()
                );
                println!("  • Provider:       {}", self.admin_provider.name());
                let router_summary = self
                    .router_registry
                    .get_status()
                    .verified_identity
                    .map(|id| id.display_summary())
                    .unwrap_or_else(|| "Unknown Router".to_string());
                println!("  • Router Identity: {}", router_summary);
                println!("  • Scope:          {}", scope);
                println!("  • New Duration:   {}", new_duration);

                let is_mock = self.router_registry.active_provider_id().as_deref() == Some("mock");
                if is_mock {
                    println!(
                        "  • Notice:         {}",
                        "[SIMULATED] Mock router test mode active — no physical hardware will be modified."
                            .bright_yellow()
                            .bold()
                    );
                } else if !auto_confirm {
                    print!(
                        "{} Confirm adjusting policy duration on physical router? [yes/N]: ",
                        "[CONFIRMATION REQUIRED]".bright_red().bold()
                    );
                    let _ = io::stdout().flush();
                    let confirm = self.read_confirmation_input().unwrap_or_default();
                    if !matches!(confirm.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
                        println!(
                            "{} Policy adjustment cancelled by administrator. Zero router mutations performed.",
                            "[INFO]".cyan().bold()
                        );
                        return;
                    }
                }

                println!(
                    "{} Adjusting policy duration via {}...",
                    "[EXEC]".cyan().bold(),
                    self.admin_provider.name()
                );

                match self
                    .admin_provider
                    .adjust_policy_duration(&scope, &new_duration)
                {
                    Ok(updated) => {
                        println!(
                            "{} Successfully updated policy duration! Policy ID: {}",
                            "[SUCCESS]".green().bold(),
                            updated.policy_id.bright_yellow()
                        );
                        if let Some(exp) = updated.expires_at_unix {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let remaining = exp.saturating_sub(now);
                            println!(
                                "  • New Expiration: {:.1} minutes remaining (Unix timestamp: {})",
                                remaining as f64 / 60.0,
                                exp
                            );
                        } else {
                            println!(
                                "  • New Duration: Indefinite (manual 'router resume' required)"
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to adjust policy duration: {}",
                            "[ERR]".red().bold(),
                            e
                        );
                    }
                }
            }
            "connect" => {
                if args.len() > 1 && args[1].eq_ignore_ascii_case("mock") {
                    if self.is_router_lab {
                        println!(
                            "{} Mock router provider is prohibited in router-lab mode. Connect to a real supported provider for hardware validation.",
                            "[ERR]".red().bold()
                        );
                        return;
                    }

                    let provider = Arc::new(MockRouterAdminProvider::new(self.iface.gateway));
                    match self
                        .router_registry
                        .connect("mock", provider.clone(), "internal://mock")
                    {
                        Ok(id) => {
                            self.admin_provider =
                                self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            println!(
                                "{} Connected to Mock Router Provider (Identity: {})",
                                "[SUCCESS]".green().bold(),
                                id.display_summary()
                            );
                        }
                        Err(e) => {
                            println!(
                                "{} Failed to connect mock provider: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                        }
                    }
                    return;
                }

                if args.len() > 1
                    && (args[1].eq_ignore_ascii_case("ssh")
                        || args[1].eq_ignore_ascii_case("openwrt-ssh"))
                {
                    let mut host = self.iface.gateway;
                    let mut port = 22;
                    let mut username = "root".to_string();
                    let mut key_path = None;
                    let mut pin_key = None;

                    let mut idx = 2;
                    while idx < args.len() {
                        let arg = args[idx];
                        if !arg.starts_with('-') && idx == 2 {
                            if let Ok(ip) = arg.parse::<Ipv4Addr>() {
                                host = ip;
                                idx += 1;
                                continue;
                            }
                        }
                        match arg.to_lowercase().as_str() {
                            "--port" | "-p" => {
                                if idx + 1 < args.len() {
                                    if let Ok(p) = args[idx + 1].parse::<u16>() {
                                        port = p;
                                        idx += 2;
                                        continue;
                                    }
                                }
                                println!("{} Invalid port specified.", "[ERR]".red().bold());
                                return;
                            }
                            "--user" | "-u" | "--username" => {
                                if idx + 1 < args.len() {
                                    username = args[idx + 1].to_string();
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing username.", "[ERR]".red().bold());
                                return;
                            }
                            "--key" | "-k" | "-i" | "--identity" => {
                                if idx + 1 < args.len() {
                                    key_path = Some(std::path::PathBuf::from(args[idx + 1]));
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing private key path.", "[ERR]".red().bold());
                                return;
                            }
                            "--pin" | "--fingerprint" => {
                                if idx + 1 < args.len() {
                                    pin_key = Some(args[idx + 1].to_string());
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing host key pin value.", "[ERR]".red().bold());
                                return;
                            }
                            _ => {
                                idx += 1;
                            }
                        }
                    }

                    match find_ssh_client() {
                        Ok(p) => {
                            println!(
                                "{} Discovered local OpenSSH client: {}",
                                "[INFO]".cyan().bold(),
                                p.display()
                            );
                        }
                        Err(e) => {
                            println!("{} {}", "[ERR]".red().bold(), e);
                            return;
                        }
                    }

                    let mut ssh_config =
                        SshConfig::new(host).with_port(port).with_username(username);
                    if let Some(key) = key_path {
                        ssh_config = ssh_config.with_key_path(key);
                    }
                    if let Some(pin) = pin_key {
                        ssh_config = ssh_config.with_pinned_host_key(pin);
                    }

                    let ssh_transport = SshOpenWrtTransport::new(ssh_config);
                    let provider =
                        OpenWrtAdminProvider::new(host, format!("ssh://{}:{}", host, port))
                            .with_transport(Box::new(ssh_transport));

                    println!(
                        "{} Connecting to OpenWrt gateway via SSH at {}:{}...",
                        "[INFO]".cyan().bold(),
                        host,
                        port
                    );

                    match provider.login() {
                        Ok(_) => match provider.detect_identity() {
                            Ok(id) => {
                                println!(
                                    "{} Successfully connected via SSH to {}!",
                                    "[SUCCESS]".green().bold(),
                                    id.display_summary()
                                );
                                println!(
                                    "  • Transport:        {}",
                                    "SSH (Strict Host Key Checking, BatchMode)".bright_cyan()
                                );
                                println!(
                                    "  • User Privileges:  {}",
                                    "Root (UID 0 verified)".bright_green().bold()
                                );
                                let provider_arc = Arc::new(provider);
                                let _ = self.router_registry.connect(
                                    "openwrt-ssh",
                                    provider_arc.clone(),
                                    format!("ssh://{}:{}", host, port),
                                );
                                self.admin_provider =
                                    self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            }
                            Err(e) => {
                                println!(
                                    "{} SSH session opened but identity check failed: {}",
                                    "[WARN]".yellow().bold(),
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "{} Failed to authenticate via SSH: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                            println!(
                                "{} Refusing to fall back to unauthenticated transports or ARP poisoning.",
                                "[SECURITY]".yellow().bold()
                            );
                        }
                    }
                } else if args.len() > 1
                    && (args[1].eq_ignore_ascii_case("mikrotik")
                        || args[1].eq_ignore_ascii_case("routeros")
                        || args[1].eq_ignore_ascii_case("mikrotik-rest"))
                {
                    let mut endpoint = None;
                    let mut username = "admin".to_string();
                    let mut ca_cert_path = None;

                    let mut idx = 2;
                    while idx < args.len() {
                        let arg = args[idx];
                        if !arg.starts_with('-') && endpoint.is_none() {
                            endpoint = Some(arg.to_string());
                            idx += 1;
                            continue;
                        }
                        match arg.to_lowercase().as_str() {
                            "--user" | "-u" | "--username" => {
                                if idx + 1 < args.len() {
                                    username = args[idx + 1].to_string();
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing username.", "[ERR]".red().bold());
                                return;
                            }
                            "--ca-cert" | "--cert" | "--ca" => {
                                if idx + 1 < args.len() {
                                    ca_cert_path = Some(std::path::PathBuf::from(args[idx + 1]));
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing CA certificate path.", "[ERR]".red().bold());
                                return;
                            }
                            _ => {
                                idx += 1;
                            }
                        }
                    }

                    let raw_endpoint = endpoint
                        .unwrap_or_else(|| format!("https://{}:443/rest", self.iface.gateway));
                    let endpoint = if !raw_endpoint.starts_with("http://")
                        && !raw_endpoint.starts_with("https://")
                    {
                        format!("https://{}/rest", raw_endpoint)
                    } else {
                        raw_endpoint.clone()
                    };

                    print!(
                        "Enter administrative password for MikroTik RouterOS user '{}': ",
                        username
                    );
                    let _ = io::stdout().flush();
                    let password = match read_masked_password() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{} Failed to read password input.", "[ERR]".red().bold());
                            return;
                        }
                    };
                    if password.is_empty() {
                        println!("{} Password cannot be empty.", "[ERR]".red().bold());
                        return;
                    }

                    let mut transport = HttpsMikroTikTransport::new();
                    if let Some(ca) = ca_cert_path {
                        transport = transport.with_ca_cert(ca);
                    }

                    let provider = MikroTikAdminProvider::new(self.iface.gateway, &endpoint)
                        .with_transport(Box::new(transport));
                    provider.set_credentials(RouterCredentials::new(username, password));

                    println!(
                        "{} Authenticating with MikroTik RouterOS gateway at {}...",
                        "[INFO]".cyan().bold(),
                        endpoint
                    );
                    match provider.login() {
                        Ok(_) => match provider.detect_identity() {
                            Ok(id) => {
                                println!(
                                    "{} Successfully connected to {}!",
                                    "[SUCCESS]".green().bold(),
                                    id.display_summary()
                                );
                                println!(
                                    "  • Transport:        {}",
                                    "HTTPS (REST API, Strict TLS & Certificate Verification)"
                                        .bright_cyan()
                                );
                                println!(
                                    "  • Enforcement:      {}",
                                    "RouterOS L3 Forward Filter Rules (icmp-network-unreachable)"
                                        .bright_green()
                                );
                                println!(
                                    "  • Autonomous Task:  {}",
                                    "RouterOS /system/script & /system/scheduler Watchdog"
                                        .bright_green()
                                );
                                let provider_arc = Arc::new(provider);
                                let _ = self.router_registry.connect(
                                    "mikrotik-rest",
                                    provider_arc.clone(),
                                    &raw_endpoint,
                                );
                                self.admin_provider =
                                    self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            }
                            Err(e) => {
                                println!(
                                    "{} Authentication succeeded but identity check failed: {}",
                                    "[WARN]".yellow().bold(),
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "{} Failed to authenticate with MikroTik RouterOS: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                            println!(
                                "{} Refusing to fall back to unencrypted HTTP, OpenWrt, or ARP poisoning.",
                                "[SECURITY]".yellow().bold()
                            );
                        }
                    }
                } else if args.len() > 1
                    && (args[1].eq_ignore_ascii_case("avm")
                        || args[1].eq_ignore_ascii_case("fritzbox")
                        || args[1].eq_ignore_ascii_case("fritz")
                        || args[1].eq_ignore_ascii_case("avm-tr064"))
                {
                    let mut endpoint = None;
                    let mut username = "admin".to_string();
                    let mut ca_cert_path = None;

                    let mut idx = 2;
                    while idx < args.len() {
                        let arg = args[idx];
                        if !arg.starts_with('-') && endpoint.is_none() {
                            endpoint = Some(arg.to_string());
                            idx += 1;
                            continue;
                        }
                        match arg.to_lowercase().as_str() {
                            "--user" | "-u" | "--username" => {
                                if idx + 1 < args.len() {
                                    username = args[idx + 1].to_string();
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing username.", "[ERR]".red().bold());
                                return;
                            }
                            "--ca-cert" | "--cert" | "--ca" => {
                                if idx + 1 < args.len() {
                                    ca_cert_path = Some(std::path::PathBuf::from(args[idx + 1]));
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing CA certificate path.", "[ERR]".red().bold());
                                return;
                            }
                            _ => {
                                idx += 1;
                            }
                        }
                    }

                    let raw_endpoint = endpoint.unwrap_or_else(|| {
                        format!("https://{}:49443/tr64desc.xml", self.iface.gateway)
                    });

                    print!(
                        "Enter administrative password for AVM FRITZ!Box user '{}': ",
                        username
                    );
                    let _ = io::stdout().flush();
                    let password = match read_masked_password() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{} Failed to read password input.", "[ERR]".red().bold());
                            return;
                        }
                    };
                    if password.is_empty() {
                        println!("{} Password cannot be empty.", "[ERR]".red().bold());
                        return;
                    }

                    let mut transport = HttpAvmTransport::new();
                    if let Some(ca) = ca_cert_path {
                        transport = transport.with_ca_cert(ca);
                    }

                    let provider = AvmAdminProvider::new(self.iface.gateway, &raw_endpoint)
                        .with_transport(Box::new(transport));
                    provider.set_credentials(RouterCredentials::new(username, password));

                    println!(
                        "{} Authenticating with AVM FRITZ!Box gateway at {}...",
                        "[INFO]".cyan().bold(),
                        raw_endpoint
                    );
                    match provider.login() {
                        Ok(_) => match provider.detect_identity() {
                            Ok(id) => {
                                println!(
                                    "{} Successfully connected to {}!",
                                    "[SUCCESS]".green().bold(),
                                    id.display_summary()
                                );
                                println!(
                                    "  • Transport:        {}",
                                    "TR-064/SOAP (HTTP Digest Authentication, Strict TLS)"
                                        .bright_cyan()
                                );
                                println!(
                                    "  • Enforcement:      {}",
                                    "AVM X_AVM-DE_HostFilter (DisallowWANAccessByIP)"
                                        .bright_green()
                                );
                                println!(
                                    "  • Management:       {}",
                                    "Router administration & intra-LAN preserved 100%"
                                        .bright_green()
                                );
                                println!(
                                    "  • Limitations:      {}",
                                    "IPv4 only (IPv6 unblocked); Autonomous timed recovery unsupported".yellow()
                                );
                                let provider_arc = Arc::new(provider);
                                let _ = self.router_registry.connect(
                                    "avm-tr064",
                                    provider_arc.clone(),
                                    &raw_endpoint,
                                );
                                self.admin_provider =
                                    self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            }
                            Err(e) => {
                                println!(
                                    "{} Authentication succeeded but identity check failed: {}",
                                    "[WARN]".yellow().bold(),
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "{} Failed to authenticate with AVM FRITZ!Box: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                            println!(
                                "{} Refusing to fall back to unauthenticated transports, OpenWrt, MikroTik, or ARP poisoning.",
                                "[SECURITY]".yellow().bold()
                            );
                        }
                    }
                } else if args.len() > 1
                    && (args[1].eq_ignore_ascii_case("unifi")
                        || args[1].eq_ignore_ascii_case("ubnt")
                        || args[1].eq_ignore_ascii_case("ubiquiti")
                        || args[1].eq_ignore_ascii_case("unifi-rest"))
                {
                    let mut endpoint = None;
                    let mut site = "default".to_string();
                    let mut username = "admin".to_string();
                    let mut ca_cert_path = None;

                    let mut idx = 2;
                    while idx < args.len() {
                        let arg = args[idx];
                        if !arg.starts_with('-') && endpoint.is_none() {
                            endpoint = Some(arg.to_string());
                            idx += 1;
                            continue;
                        }
                        match arg.to_lowercase().as_str() {
                            "--site" | "-s" => {
                                if idx + 1 < args.len() {
                                    site = args[idx + 1].to_string();
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing site identifier.", "[ERR]".red().bold());
                                return;
                            }
                            "--user" | "-u" | "--username" => {
                                if idx + 1 < args.len() {
                                    username = args[idx + 1].to_string();
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing username.", "[ERR]".red().bold());
                                return;
                            }
                            "--ca-cert" | "--cert" | "--ca" => {
                                if idx + 1 < args.len() {
                                    ca_cert_path = Some(std::path::PathBuf::from(args[idx + 1]));
                                    idx += 2;
                                    continue;
                                }
                                println!("{} Missing CA certificate path.", "[ERR]".red().bold());
                                return;
                            }
                            _ => {
                                idx += 1;
                            }
                        }
                    }

                    let raw_endpoint =
                        endpoint.unwrap_or_else(|| format!("https://{}:443", self.iface.gateway));

                    print!(
                        "Enter administrative password or API key for UniFi user '{}': ",
                        username
                    );
                    let _ = io::stdout().flush();
                    let password = match read_masked_password() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{} Failed to read password input.", "[ERR]".red().bold());
                            return;
                        }
                    };
                    if password.is_empty() {
                        println!(
                            "{} Password or API key cannot be empty.",
                            "[ERR]".red().bold()
                        );
                        return;
                    }

                    let mut transport = HttpUnifiTransport::new();
                    if let Some(ca) = ca_cert_path {
                        transport = transport.with_ca_cert(ca);
                    }

                    let provider = UnifiAdminProvider::new(self.iface.gateway, &raw_endpoint)
                        .with_site(site.clone())
                        .with_transport(Box::new(transport));
                    provider.set_credentials(RouterCredentials::new(username, password));

                    println!(
                        "{} Authenticating with Ubiquiti UniFi Controller at {} (Site: {})...",
                        "[INFO]".cyan().bold(),
                        raw_endpoint,
                        site
                    );
                    match provider.login() {
                        Ok(_) => match provider.detect_identity() {
                            Ok(id) => {
                                println!(
                                    "{} Successfully connected to {}!",
                                    "[SUCCESS]".green().bold(),
                                    id.display_summary()
                                );
                                println!(
                                    "  • Transport:        {}",
                                    "HTTPS REST (Session Token & Strict TLS Verification)"
                                        .bright_cyan()
                                );
                                println!("  • Active Site:      {}", site.bright_green().bold());
                                println!(
                                    "  • Enforcement:      {}",
                                    "UniFi Traffic Rules Engine (Per-Device IP & MAC Block)"
                                        .bright_green()
                                );
                                println!(
                                    "  • Management:       {}",
                                    "UniFi Console & intra-LAN switching preserved 100%"
                                        .bright_green()
                                );
                                let provider_arc = Arc::new(provider);
                                let _ = self.router_registry.connect(
                                    "unifi-rest",
                                    provider_arc.clone(),
                                    &raw_endpoint,
                                );
                                self.admin_provider =
                                    self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            }
                            Err(e) => {
                                println!(
                                    "{} Authentication succeeded but identity check failed: {}",
                                    "[WARN]".yellow().bold(),
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "{} Failed to authenticate with UniFi Controller: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                            println!(
                                "{} Refusing to fall back to unauthenticated transports or ARP poisoning.",
                                "[SECURITY]".yellow().bold()
                            );
                        }
                    }
                } else {
                    let endpoint = if args.len() > 1
                        && !args[1].starts_with('-')
                        && !args[1].eq_ignore_ascii_case("http")
                    {
                        args[1].to_string()
                    } else if args.len() > 2
                        && args[1].eq_ignore_ascii_case("http")
                        && !args[2].starts_with('-')
                    {
                        args[2].to_string()
                    } else {
                        format!("http://{}:80/ubus", self.iface.gateway)
                    };

                    let username = if let Some(pos) = args
                        .iter()
                        .position(|&a| a == "--user" || a == "-u" || a == "--username")
                    {
                        args.get(pos + 1)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "root".to_string())
                    } else {
                        "root".to_string()
                    };

                    print!(
                        "Enter administrative password for OpenWrt user '{}': ",
                        username
                    );
                    let _ = io::stdout().flush();
                    let password = match read_masked_password() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{} Failed to read password input.", "[ERR]".red().bold());
                            return;
                        }
                    };
                    if password.is_empty() {
                        println!("{} Password cannot be empty.", "[ERR]".red().bold());
                        return;
                    }

                    let provider = OpenWrtAdminProvider::new(self.iface.gateway, &endpoint);
                    provider.set_credentials(RouterCredentials::new(username, password));

                    println!(
                        "{} Authenticating with OpenWrt gateway at {}...",
                        "[INFO]".cyan().bold(),
                        endpoint
                    );
                    match provider.login() {
                        Ok(_) => match provider.detect_identity() {
                            Ok(id) => {
                                println!(
                                    "{} Successfully connected to {}!",
                                    "[SUCCESS]".green().bold(),
                                    id.display_summary()
                                );
                                let provider_arc = Arc::new(provider);
                                let _ = self.router_registry.connect(
                                    "openwrt-http",
                                    provider_arc.clone(),
                                    &endpoint,
                                );
                                self.admin_provider =
                                    self.policy_engine.clone() as Arc<dyn RouterAdminProvider>;
                            }
                            Err(e) => {
                                println!(
                                    "{} Authentication succeeded but identity check failed: {}",
                                    "[WARN]".yellow().bold(),
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "{} Failed to authenticate with OpenWrt router: {}",
                                "[ERR]".red().bold(),
                                e
                            );
                        }
                    }
                }
            }
            _ => {
                println!(
                    "{} Unknown router subcommand '{}'. Use 'router help' for available commands.",
                    "[WARN]".yellow().bold(),
                    args[0]
                );
            }
        }
    }

    fn resolve_single_target(&self, arg: &str) -> Result<(Ipv4Addr, Option<MacAddress>), String> {
        if let Ok(ip) = arg.parse::<Ipv4Addr>() {
            let mac = self.hosts.iter().find(|h| h.ip == ip).map(|h| h.mac);
            return Ok((ip, mac));
        }
        if let Ok(id) = arg.parse::<usize>() {
            if let Some(h) = self.hosts.iter().find(|h| h.id == id) {
                return Ok((h.ip, Some(h.mac)));
            } else {
                return Err(format!("Device ID {} not found in known hosts table.", id));
            }
        }
        Err(format!("Invalid target '{}'. Expected 'all', a device ID (e.g. 1), or IPv4 address (e.g. 192.168.1.50).", arg))
    }

    fn show_policy_detail(&self, policy_id: &str) {
        match self.policy_engine.get_policy_detail(policy_id) {
            Some(detail) => {
                render_router_policy_detail(&detail);
            }
            None => {
                println!(
                    "{} Policy ID '{}' not found in active router policies or persistent history records.",
                    "[ERR]".red().bold(),
                    policy_id
                );
                println!(
                    "  Use 'router policies' to list all registered and historical policy IDs."
                );
            }
        }
    }
}

impl Drop for RustrictCli {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Resolves target argument into a list of unique host IDs.
/// Supports:
/// - "all" -> all known host IDs
/// - Device IDs (e.g. "0", "1")
/// - IPv4 addresses (e.g. "192.168.18.50")
/// - Mixed comma-separated lists (e.g. "0,192.168.18.50,2")
///
/// Performs strictly in-memory lookup against hosts with zero network scanning.
pub fn resolve_targets(hosts: &[Host], arg: &str) -> Result<Vec<usize>, String> {
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        if hosts.is_empty() {
            return Err("No devices in inventory. Run 'scan' or 'add <ip>' first.".to_string());
        }
        return Ok(hosts.iter().map(|h| h.id).collect());
    }

    let mut ids = Vec::new();
    for token in trimmed.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }

        if let Ok(id) = t.parse::<usize>() {
            if hosts.iter().any(|h| h.id == id) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            } else {
                return Err(format!(
                    "Device with ID {} not found in known hosts table.",
                    id
                ));
            }
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            let matches: Vec<usize> = hosts.iter().filter(|h| h.ip == ip).map(|h| h.id).collect();

            if matches.is_empty() {
                return Err(format!(
                    "Device with IP {} is not in the known hosts table. Run 'scan' or use 'add {}' first.",
                    ip, ip
                ));
            } else if matches.len() > 1 {
                return Err(format!(
                    "Ambiguous identifier: IP {} maps to multiple devices (IDs: {:?}). Specify target by unique Device ID.",
                    ip, matches
                ));
            } else {
                let id = matches[0];
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        } else {
            return Err(format!(
                "Invalid device identifier '{}'. Expected a Device ID (e.g. 1) or IPv4 address (e.g. 192.168.18.50).",
                t
            ));
        }
    }

    if ids.is_empty() {
        return Err("No valid device targets specified.".to_string());
    }

    Ok(ids)
}
