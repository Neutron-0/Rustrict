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

                return res.map(|_| input.trim().to_string());
            }
        }
    }

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
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

        let scope = if let Some(ref saved_scope) = persistent_state.scope {
            saved_scope.clone()
        } else {
            let mut s = ScopeManager::default();
            let prefix = u32::from(iface.netmask).count_ones() as u8;
            if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
                s.add_cidr_direct(local_cidr);
            }
            s
        };

        let mut hosts = Vec::new();

        if !persistent_state.blocked_hosts.is_empty() {
            println!(
                "{} Restoring {} persistent blocked device(s) from state...",
                "[INFO]".cyan().bold(),
                persistent_state.blocked_hosts.len()
            );
            for (idx, b) in persistent_state.blocked_hosts.iter().enumerate() {
                let mac = b.mac.parse::<MacAddress>().unwrap_or(MacAddress::ZERO);
                if mac.is_zero() {
                    continue;
                }
                if let Err(e) = scope.validate_target(&b.ip, Some(&mac)) {
                    println!(
                        "{} Skipping restored blocked device {} ({}) due to scope violation: {}",
                        "[WARN]".yellow().bold(),
                        b.ip,
                        b.mac,
                        e
                    );
                    continue;
                }
                let dir = persistent_state.get_direction(&b.ip);
                let mut host = Host::with_source(
                    idx,
                    b.ip,
                    mac,
                    b.name.clone(),
                    crate::types::NameSource::Manual,
                    "Saved Block".to_string(),
                );
                host.status = HostStatus::Blocked(dir);
                host.persistent_block = true;
                host.online = false; // Will be verified online during scan
                spoofer.add(host.clone());
                limiter.block(host.ip, dir);
                hosts.push(host);
            }
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
        }
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
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, 24) {
            scope.add_cidr_direct(local_cidr);
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
            hosts: Vec::new(),
            persistent_state,
            scope,
            services: HashMap::new(),
            findings: Vec::new(),
            admin_provider,
            router_registry,
            policy_engine,
            simulated_inputs: Vec::new(),
        }
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

    pub fn run_interactive(&mut self) {
        let stdin = io::stdin();

        loop {
            print!("{} ", "rustrict >".bright_red().bold());
            io::stdout().flush().unwrap();

            let mut line = String::new();
            if stdin.read_line(&mut line).is_err() || line.trim().is_empty() {
                continue;
            }

            let input = line.trim();
            let args: Vec<&str> = input.split_whitespace().collect();
            if args.is_empty() {
                continue;
            }

            match args[0].to_lowercase().as_str() {
                "scan" => self.handle_scan(&args[1..]),
                "hosts" => self.handle_hosts(),
                "scope" => self.handle_scope(&args[1..]),
                "ports" => self.handle_ports(&args[1..]),
                "audit" => self.handle_audit(&args[1..]),
                "simulate" => self.handle_simulate(&args[1..]),
                "export" => self.handle_export(&args[1..]),
                "limit" => self.handle_limit(&args[1..]),
                "block" => self.handle_block(&args[1..]),
                "free" => self.handle_free(&args[1..]),
                "add" => self.handle_add(&args[1..]),
                "router" => self.handle_router(&args[1..]),
                "clear" | "cls" => {
                    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
                    let _ = io::stdout().flush();
                }
                "help" | "?" => self.print_help(),
                "quit" | "exit" => {
                    self.shutdown();
                    println!("Exiting rustrict. Active session stopped.");
                    break;
                }
                cmd => println!("{}: command not found. Type 'help' for commands.", cmd),
            }
        }
    }

    fn handle_scan(&mut self, args: &[&str]) {
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
            println!("No hosts discovered yet. Run 'scan' first.");
            return;
        }

        // Sort by IP ascending and re-index
        self.hosts.sort_by_key(|h| u32::from(h.ip));
        for (i, h) in self.hosts.iter_mut().enumerate() {
            h.id = i;
        }

        render_hosts_table(&self.hosts);
    }

    fn handle_limit(&mut self, args: &[&str]) {
        if args.len() < 2 {
            println!("Usage: limit <id|ip|all> <rate> [--upload] [--download]");
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

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        for id in ids {
            if let Some(host) = self.hosts.iter_mut().find(|h| h.id == id) {
                if let Err(reason) = self.scope.validate_target(&host.ip, Some(&host.mac)) {
                    println!(
                        "{} Scope Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }
                host.status = HostStatus::Limited(rate, dir);
                self.spoofer.add(host.clone());
                self.limiter.limit(host.ip, dir, rate);
                println!(
                    "{} Limited {} to {} ({})",
                    "OK".green().bold(),
                    host.ip,
                    rate,
                    dir.pretty()
                );
            }
        }
    }

    fn handle_block(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: block <id|ip|all> [--upload] [--download]");
            return;
        }

        let mut dir = Direction::Both;
        if args.contains(&"--upload") && !args.contains(&"--download") {
            dir = Direction::Outgoing;
        } else if args.contains(&"--download") && !args.contains(&"--upload") {
            dir = Direction::Incoming;
        }

        let ids = match self.resolve_targets(args[0]) {
            Ok(ids) => ids,
            Err(e) => {
                println!("{} {}", "[ERR]".red().bold(), e);
                return;
            }
        };

        for id in ids {
            if let Some(host) = self.hosts.iter_mut().find(|h| h.id == id) {
                if let Err(reason) = self.scope.validate_target(&host.ip, Some(&host.mac)) {
                    println!(
                        "{} Scope Error for {}: {}",
                        "[ERR]".red().bold(),
                        host.ip,
                        reason
                    );
                    continue;
                }
                host.status = HostStatus::Blocked(dir);
                host.persistent_block = true;
                self.persistent_state.add_blocked(host, dir);
                self.spoofer.add(host.clone());
                self.limiter.block(host.ip, dir);
                println!(
                    "{} Blocked {} ({}) [Persistent]",
                    "OK".green().bold(),
                    host.ip,
                    dir.pretty()
                );
            }
        }
    }

    fn handle_free(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: free <id|ip|all>");
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

    fn handle_add(&mut self, args: &[&str]) {
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
                // Ensure persistent block is continuously enforced
                if existing.persistent_block {
                    if let HostStatus::Blocked(dir) = existing.status {
                        self.spoofer.add(existing.clone());
                        self.limiter.block(existing.ip, dir);
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

    fn handle_scope(&mut self, args: &[&str]) {
        if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
            render_scope_table(&self.scope);
            return;
        }

        match args[0].to_lowercase().as_str() {
            "add" => {
                if args.len() < 2 {
                    println!("Usage: scope add <cidr> (e.g. scope add 192.168.1.0/24)");
                    return;
                }
                match args[1].parse::<Ipv4Cidr>() {
                    Ok(cidr) => {
                        self.scope.add_cidr_direct(cidr.clone());
                        self.persistent_state.scope = Some(self.scope.clone());
                        let _ = self.persistent_state.save();
                        println!("{} Added CIDR {} to operational scope", "OK".green().bold(), cidr);
                    }
                    Err(e) => println!("{} Failed to parse CIDR: {}", "[ERR]".red().bold(), e),
                }
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
            _ => println!("Usage: scope [status | add <cidr> | remove <cidr> | exclude-ip <ip> | exclude-mac <mac> | strict <on|off>]"),
        }
    }

    fn handle_ports(&mut self, args: &[&str]) {
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

    fn handle_audit(&mut self, args: &[&str]) {
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

    fn handle_simulate(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: simulate <id|ip|all> [drop <0-100>] [delay <ms>] [jitter <ms>] OR simulate <id|ip|all> clear");
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

                self.spoofer.add(host.clone());
                self.limiter.set_fault(host.ip, profile.clone());
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
    }

    fn handle_export(&self, args: &[&str]) {
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
        println!("{}", "rustrict Commands:".bright_yellow().bold());
        println!("  scan [--range <start-end>] [--fresh] [--ports]  Scans network (use --ports for service enumeration)");
        println!("  hosts                                           Displays discovered hosts and live online/offline state");
        println!("  scope [status|add|remove|exclude-ip|strict]     Manages authorized targets and operational boundaries");
        println!("  ports <id|ip|all> [port-range]                  Enumerates open TCP services and grabs service banners");
        println!("  audit <id|ip|all>                               Performs active security posture checks (TLS & SMB)");
        println!("  simulate <id|ip|all> [drop %] [delay ms] [...]  Simulates network resilience and fault injection");
        println!("  export [markdown|json|sarif] [filename]         Exports structured assessment reports and evidence");
        println!("  limit <id|ip|all> <rate> [...]                  Limits bandwidth (e.g. limit 1 200kbit, limit all 1mbit)");
        println!("  block <id|ip|all> [...]                         Blocks host internet access [Persists across restarts]");
        println!("  free <id|ip|all>                                Removes limits and unblocks host [Clears persistent rule]");
        println!("  add <ip> [--mac <mac>]                          Manually adds a host to table");
        println!("  router [capabilities|status|policies|preview|pause|resume|adjust|connect] [...] Router administration via authenticated firewall");
        println!("  clear                                           Clears screen");
        println!("  quit / exit                                     Exits rustrict and restores network\n");
    }

    pub fn handle_router(&mut self, args: &[&str]) {
        if args.is_empty() || args[0].eq_ignore_ascii_case("help") {
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
                            if let Err(e) = self.scope.validate_target(&ip, mac.as_ref()) {
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
                            if let Err(e) = self.scope.validate_target(&ip, mac.as_ref()) {
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
