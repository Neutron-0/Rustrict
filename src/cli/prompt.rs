use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use colored::*;

use crate::cli::table::{
    render_findings_table, render_hosts_table, render_scope_table, render_services_table,
};
use crate::core::assessment::{AuditFinding, ServiceEntry};
use crate::core::scope::{Ipv4Cidr, ScopeManager};
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
        let mut hosts = Vec::new();

        if !persistent_state.blocked_hosts.is_empty() {
            println!(
                "{} Restoring {} persistent blocked device(s) from state...",
                "[INFO]".cyan().bold(),
                persistent_state.blocked_hosts.len()
            );
            for (idx, b) in persistent_state.blocked_hosts.iter().enumerate() {
                let mac = b.mac.parse::<MacAddress>().unwrap_or(MacAddress::ZERO);
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

        let mut scope = ScopeManager::default();
        let prefix = u32::from(iface.netmask).count_ones() as u8;
        if let Ok(local_cidr) = Ipv4Cidr::new(iface.ip, prefix) {
            scope.add_cidr_direct(local_cidr);
        }


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
        }
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
            println!("{}", "Performing clean fresh scan (bypassing cache)...".bright_yellow());
        } else {
            println!("{}", "Scanning subnet for online hosts...".yellow());
        }
        let t0 = std::time::Instant::now();

        let mut custom_range = None;
        if let Some(pos) = args.iter().position(|&a| a == "--range") {
            if pos + 1 < args.len() {
                let parts: Vec<&str> = args[pos + 1].split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<Ipv4Addr>()) {
                        custom_range = Some((start, end));
                    }
                }
            }
        }

        let progress_cb = |scanned: usize, total: usize, discovered: usize| {
            let width = 28;
            let ratio = if total > 0 { (scanned as f64) / (total as f64) } else { 1.0 };
            let filled = ((ratio * width as f64) as usize).min(width);
            let empty = width - filled;

            let bar = format!("{}{}", "█".repeat(filled).bright_cyan(), "░".repeat(empty).white().dimmed());
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
            println!("\n{} Performing service enumeration on discovered hosts...", "[SCAN]".cyan().bold());
            let online_ips: Vec<Ipv4Addr> = self.hosts.iter().filter(|h| h.online).map(|h| h.ip).collect();
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
            if let Some(existing) = self.hosts.iter_mut().find(|h| h.ip == ip || (mac != MacAddress::ZERO && h.mac == mac)) {
                existing.name = name;
                existing.name_source = crate::types::NameSource::Dhcp;
                existing.online = true;
            } else {
                let id = self.hosts.len();
                let vendor = crate::resolver::oui::lookup_vendor(&mac).to_string();
                let mut new_h = Host::with_source(
                    id,
                    ip,
                    mac,
                    name,
                    crate::types::NameSource::Dhcp,
                    vendor,
                );
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
                    println!("{} Scope Error for {}: {}", "[ERR]".red().bold(), host.ip, reason);
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
                    println!("{} Scope Error for {}: {}", "[ERR]".red().bold(), host.ip, reason);
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

        let identity = crate::resolver::resolve_identity(ip, &mac, self.iface.ip, self.iface.gateway);

        // Check if host already exists; update it instead of creating duplicates
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.ip == ip) {
            existing.mac = mac;
            existing.name = identity.hostname;
            existing.name_source = identity.source;
            existing.vendor = identity.vendor;
            println!("{} Updated existing host {} ({})", "OK".green().bold(), existing.ip, existing.mac);
        } else {
            let id = self.hosts.len();
            let host = Host::with_source(id, ip, mac, identity.hostname, identity.source, identity.vendor);
            println!("{} Added host {} ({})", "OK".green().bold(), host.ip, host.mac);
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
                    || new_hosts.iter().any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac))
            });
        }

        // Update reachability flags for remaining existing hosts
        for h in &mut self.hosts {
            let is_alive = new_hosts.iter().any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac));
            h.online = is_alive;
        }

        // Upsert newly discovered/confirmed hosts
        for new_h in new_hosts {
            if let Some(existing) = self.hosts.iter_mut().find(|h| {
                (h.mac != MacAddress::ZERO && h.mac == new_h.mac) || h.ip == new_h.ip
            }) {
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
                        println!("{} Scope strict mode ENABLED (out-of-scope targets blocked)", "OK".green().bold());
                    }
                    "off" | "false" | "0" => {
                        self.scope.set_strict(false);
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
                    println!("{} Scope Error for {}: {}", "[ERR]".red().bold(), host.ip, reason);
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
                    println!("{} Scope Error for {}: {}", "[ERR]".red().bold(), host.ip, reason);
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
                        if (name_lower.contains("ssl") || name_lower.contains("https") || name_lower.contains("tls"))
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
                    if !self.findings.iter().any(|ex| ex.rule_id == f.rule_id && ex.target_ip == f.target_ip && ex.port == f.port) {
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
                    println!("{} Cleared fault simulation for {}", "OK".green().bold(), host.ip);
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
                    println!("{} Scope Error for {}: {}", "[ERR]".red().bold(), host.ip, reason);
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
        let fmt = args.first().map(|s| s.to_lowercase()).unwrap_or_else(|| "markdown".to_string());
        let default_filename = match fmt.as_str() {
            "json" => "rustrict-assessment.json",
            "sarif" => "rustrict-assessment.sarif",
            _ => "rustrict-assessment.md",
        };
        let target_file = args.get(1).unwrap_or(&default_filename);

        let result = match fmt.as_str() {
            "json" => crate::cli::export::export_json(&self.scope, &self.services, &self.findings)
                .map_err(|e| e.to_string()),
            "sarif" => crate::cli::export::export_sarif(&self.findings)
                .map_err(|e| e.to_string()),
            "markdown" | "md" => Ok(crate::cli::export::export_markdown(&self.scope, &self.services, &self.findings)),
            _ => Ok(crate::cli::export::export_markdown(&self.scope, &self.services, &self.findings)),
        };


        match result {
            Ok(content) => {
                match crate::cli::export::save_report(target_file, &content) {
                    Ok(_) => {
                        println!(
                            "{} Successfully exported assessment report to '{}' ({} bytes)",
                            "OK".green().bold(),
                            target_file,
                            content.len()
                        );
                    }
                    Err(e) => {
                        println!("{} Failed to write report to '{}': {}", "[ERR]".red().bold(), target_file, e);
                    }
                }
            }
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
        println!("  clear                                           Clears screen");
        println!("  quit / exit                                     Exits rustrict and restores network\n");
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
                return Err(format!("Device with ID {} not found in known hosts table.", id));
            }
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            let matches: Vec<usize> = hosts
                .iter()
                .filter(|h| h.ip == ip)
                .map(|h| h.id)
                .collect();

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
