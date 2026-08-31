use std::io::{self, Write};
use std::net::Ipv4Addr;
use colored::*;

use crate::cli::table::render_hosts_table;
use crate::limiter::TrafficLimiter;
use crate::types::NetworkInterface;
use crate::scanner::SubnetScanner;
use crate::spoofer::ArpSpoofer;
use crate::types::{BitRate, Direction, Host, HostStatus, MacAddress};

pub struct RustrictCli {
    #[allow(dead_code)]
    iface: NetworkInterface,
    scanner: SubnetScanner,
    spoofer: ArpSpoofer,
    limiter: TrafficLimiter,
    sniffer: crate::resolver::passive::PassiveIdentitySniffer,
    hosts: Vec<Host>,
    persistent_state: crate::state::PersistentState,
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

        Self {
            iface,
            scanner,
            spoofer,
            limiter,
            sniffer,
            hosts,
            persistent_state,
        }
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
                    self.limiter.stop();
                    self.spoofer.stop();
                    self.sniffer.stop();
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

    /// Resolves target argument into a list of unique host IDs.
    /// Supports:
    /// - "all" -> all known host IDs
    /// - Device IDs (e.g. "0", "1")
    /// - IPv4 addresses (e.g. "192.168.18.50")
    /// - Mixed comma-separated lists (e.g. "0,192.168.18.50,2")
    /// Performs strictly in-memory lookup against self.hosts with zero network scanning.
    fn resolve_targets(&self, arg: &str) -> Result<Vec<usize>, String> {
        let trimmed = arg.trim();
        if trimmed.eq_ignore_ascii_case("all") {
            if self.hosts.is_empty() {
                return Err("No devices in inventory. Run 'scan' or 'add <ip>' first.".to_string());
            }
            return Ok(self.hosts.iter().map(|h| h.id).collect());
        }

        let mut ids = Vec::new();
        for token in trimmed.split(',') {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }

            if let Ok(id) = t.parse::<usize>() {
                if self.hosts.iter().any(|h| h.id == id) {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                } else {
                    return Err(format!("Device with ID {} not found in known hosts table.", id));
                }
            } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
                let matches: Vec<usize> = self.hosts
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

    fn print_help(&self) {
        println!("{}", "rustrict Commands:".bright_yellow().bold());
        println!("  scan [--range <start-end>] [--fresh]  Scans network (use --fresh to clear stale devices)");
        println!("  hosts                                 Displays discovered hosts and live online/offline state");
        println!("  limit <id|ip|all> <rate> [...]        Limits bandwidth (e.g. limit 1 200kbit, limit 192.168.18.50 1mbit)");
        println!("  block <id|ip|all> [...]               Blocks host internet access [Persists across scans & restarts]");
        println!("  free <id|ip|all>                      Removes limits and unblocks host [Removes persistent rule]");
        println!("  add <ip> [--mac <mac>]                Manually adds a host to table");
        println!("  clear                                 Clears screen");
        println!("  quit / exit                           Exits rustrict and restores network\n");
    }
}
