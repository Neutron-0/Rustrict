use colored::*;
use rustrict::cli::{print_banner, RustrictCli};
use rustrict::platform;
use rustrict::types::NetworkInterface;

fn print_cli_usage() {
    println!(
        "{}",
        "Rustrict - Advanced Network Bandwidth Limiter & Controller".bold()
    );
    println!("\n{}", "USAGE:".bold());
    println!("  rustrict [OPTIONS]");
    println!("  rustrict nic [COMMAND] [ARGS...]");
    println!("\n{}", "OPTIONS:".bold());
    println!("  -h, --help                  Show this comprehensive help message and exit");
    println!("  -v, --version               Show version and architecture information");
    println!(
        "  -l, --list-interfaces       List all detected network adapters and link information"
    );
    println!("  -i, --interface <NAME|IDX>  Bind to the specified network interface name, alias, or index");
    println!("      --offline, --no-adapter Run in decoupled offline mode without binding to any physical adapter");
    println!("      --router-lab            Run in read-only router lab mode (zero active probes/mutations)");
    println!("      --strict                Start with strict scope mode enabled (enforce explicit CIDRs)");
    println!("      --permissive            Start with permissive scope mode (allow all RFC 1918 private LANs)");
    println!("      --blockmode <MODE>      Set block enforcement mode: 'blackhole' (L2 drop) or 'mitm' (WinDivert kernel drop)");
    println!("\n{}", "SUBCOMMANDS (READ-ONLY):".bold());
    println!("  nic                         Run 2-second real-time health sampling on the active adapter");
    println!(
        "  nic list                    List detected physical network adapters and link states"
    );
    println!(
        "  nic status [NAME|IDX]       Sample health, error rates, and packet metrics for adapter"
    );
    println!("\n{}", "INTERACTIVE REPL COMMANDS:".bold());
    println!("  scan                        Discover active hosts on local subnet");
    println!("  hosts / devices             List discovered hosts and their enforcement status");
    println!("  block <IP|IDX...>           Block target devices from Internet and LAN access");
    println!(
        "  free / unblock <IP|IDX...>  Unblock target devices and restore genuine gateway routes"
    );
    println!(
        "  limit <IP> <RATE>           Enforce bandwidth caps (e.g. limit 192.168.1.50 1mbps)"
    );
    println!("  blockmode [blackhole|mitm]  Toggle between L2 blackhole dropping and WinDivert kernel drop");
    println!("  scope [on|off|add|list]     Manage target admission boundaries ('scope off' permits all LANs)");
    println!(
        "  scope add all               Quickly authorize all RFC 1918 private subnets into scope"
    );
    println!(
        "  status                      Show complete system, adapter, limiter, and scope telemetry"
    );
    println!("  upgrade / update            View update instructions and run self-upgrade");
    println!("  quit / exit                 Safely restore all network states and shut down");
    println!();
}

fn main() {
    platform::enable_ansi_support();

    let args: Vec<String> = std::env::args().collect();

    // 0. Standalone commands that do NOT require administrator privileges or live network bindings:
    if args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a.eq_ignore_ascii_case("help"))
    {
        print_banner("2.0.2");
        print_cli_usage();
        return;
    }

    if args
        .iter()
        .any(|a| a == "--version" || a == "-v" || a.eq_ignore_ascii_case("version"))
    {
        println!("rustrict 2.0.2 (x86_64-pc-windows-msvc)");
        return;
    }

    if args
        .iter()
        .any(|a| a == "--list-interfaces" || a == "-l" || a.eq_ignore_ascii_case("interfaces"))
    {
        print_banner("2.0.2");
        match platform::list_network_interfaces() {
            Ok(interfaces) => {
                println!("{}", "Detected Network Adapters:".bright_yellow().bold());
                println!(
                    "  {:<6} {:<24} {:<14} {:<20} {:<18} {}",
                    "Index".bold(),
                    "Name".bold(),
                    "Status".bold(),
                    "IPv4 Address".bold(),
                    "MAC Address".bold(),
                    "Description".bold()
                );
                println!("  {}", "-".repeat(95));
                for iface in interfaces {
                    let status_colored = if iface.status.eq_ignore_ascii_case("Up") {
                        iface.status.bright_green().bold()
                    } else {
                        iface.status.dimmed()
                    };
                    let ip_str = match (iface.ip, iface.prefix_len) {
                        (Some(ip), Some(p)) => format!("{}/{}", ip, p),
                        (Some(ip), None) => ip.to_string(),
                        _ => "(no IPv4)".dimmed().to_string(),
                    };
                    println!(
                        "  [{:>3}]  {:<24} {:<14} {:<20} {:<18} {}",
                        iface.index,
                        iface.name.bright_white().bold(),
                        status_colored,
                        ip_str.bright_cyan(),
                        iface.mac.to_string(),
                        iface.description
                    );
                }
                println!();
                println!(
                    "Run 'rustrict --interface <Name|Index>' to launch with a specific adapter."
                );
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to query network interfaces: {}",
                    "[ERR]".bright_red().bold(),
                    e
                );
                std::process::exit(1);
            }
        }
        return;
    }

    if args.len() > 1
        && (args[1].eq_ignore_ascii_case("nic") || args[1].eq_ignore_ascii_case("adapter"))
    {
        let arg_slices: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        let provider = rustrict::monitor::nic::WindowsPowershellNicProvider::default();
        if let Err(e) = rustrict::monitor::nic::run_nic_cli(&provider, None, &arg_slices) {
            eprintln!("{} {}", "[ERR]".bright_red().bold(), e);
            std::process::exit(1);
        }
        return;
    }

    print_banner("2.0.2");

    let is_router_lab = args.iter().any(|a| a == "--router-lab");
    let is_offline = args.iter().any(|a| a == "--offline" || a == "--no-adapter");

    // Parse specified interface flag: -i <val> or --interface <val>
    let mut specified_interface: Option<String> = None;
    for (i, arg) in args.iter().enumerate() {
        if (arg == "-i" || arg == "--interface") && i + 1 < args.len() {
            specified_interface = Some(args[i + 1].clone());
            break;
        } else if let Some(val) = arg.strip_prefix("--interface=") {
            specified_interface = Some(val.to_string());
            break;
        }
    }

    // 1. Run Pre-flight Environment Diagnostics
    let env_status = if is_router_lab || is_offline {
        platform::check_router_lab_environment()
    } else {
        platform::check_environment()
    };

    if !is_router_lab && !is_offline && !env_status.is_admin {
        eprintln!(
            "{} Please run as Administrator (open PowerShell or Command Prompt as Administrator).",
            "[ERR]".bright_red().bold()
        );
        eprintln!("     Or run with '--offline' to inspect state and scopes without administrator privileges.");
        std::process::exit(1);
    }

    if is_router_lab {
        println!(
            "{} Operating in READ-ONLY Router-Lab mode (--router-lab active).",
            "[MODE]".bright_cyan().bold()
        );
        if !env_status.is_admin {
            println!(
                "{} Running with standard-user privileges (Administrator not required in router-lab mode).",
                "[INFO]".cyan().bold()
            );
        }
        println!(
            "     Local packet injection (Npcap/WinDivert), active probes, and OS forwarding mutations are disabled.\n"
        );
    } else if is_offline {
        println!(
            "{} Operating in DECOUPLED OFFLINE mode (--offline active).",
            "[MODE]".bright_yellow().bold()
        );
        println!("     Physical adapter binding and live packet injection are decoupled.\n");
    } else {
        if !env_status.npcap_available {
            eprintln!(
                "{} Warning: {}",
                "[WARN]".yellow().bold(),
                env_status.npcap_details
            );
        }
        if !env_status.windivert_available {
            eprintln!(
                "{} Warning: {}",
                "[WARN]".yellow().bold(),
                env_status.windivert_details
            );
        }
    }

    // 2. Discover network interface
    let mut app = if is_offline {
        let iface = platform::get_offline_interface();
        println!(
            "{} Active interface: {}",
            "OK".bright_green().bold(),
            iface.name.bright_cyan().bold()
        );
        println!(
            "     Decoupled session: Local IP {} (no live network probing)\n",
            iface.ip
        );
        RustrictCli::new(iface)
    } else if is_router_lab {
        let resolver = platform::SystemReadOnlyInterfaceResolver;
        match RustrictCli::bootstrap_router_lab(&resolver) {
            Ok(cli) => {
                let iface = cli.iface();
                println!(
                    "{} Resolved default interface (read-only): {}",
                    "OK".bright_green().bold(),
                    iface.name.bright_cyan().bold()
                );
                let gateway_mac_str = if iface.gateway_mac.is_zero() {
                    "unresolved (read-only mode; zero network probes)"
                        .yellow()
                        .to_string()
                } else {
                    format!("{} (cached)", iface.gateway_mac)
                };
                println!(
                    "     IP: {}  |  Netmask: {}  |  Gateway: {} ({})\n",
                    iface.ip.to_string().bright_white(),
                    iface.netmask.to_string().bright_white(),
                    iface.gateway.to_string().bright_white(),
                    gateway_mac_str
                );
                cli
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to resolve network interface in read-only router-lab mode: {}",
                    "[ERR]".bright_red().bold(),
                    e
                );
                std::process::exit(1);
            }
        }
    } else {
        let iface: NetworkInterface = if let Some(ref id) = specified_interface {
            match platform::get_interface_by_name_or_index(id) {
                Ok(iface) => iface,
                Err(e) => {
                    eprintln!(
                        "{} Failed to bind interface '{}': {}",
                        "[ERR]".bright_red().bold(),
                        id,
                        e
                    );
                    std::process::exit(1);
                }
            }
        } else {
            match platform::get_default_interface() {
                Ok(iface) => iface,
                Err(e) => {
                    eprintln!(
                        "{} Failed to automatically resolve default network interface: {}",
                        "[ERR]".bright_red().bold(),
                        e
                    );
                    eprintln!(
                        "\n{} Available adapters on this machine:",
                        "[INFO]".cyan().bold()
                    );
                    if let Ok(adapters) = platform::list_network_interfaces() {
                        for a in adapters {
                            println!(
                                "  [{:>2}] {:<22} Status: {:<12} IP: {}",
                                a.index,
                                a.name.bold(),
                                a.status,
                                a.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into())
                            );
                        }
                    }
                    eprintln!(
                        "\nPlease run with '--interface <Name|Index>' to select an adapter, or '--offline' to run decoupled."
                    );
                    std::process::exit(1);
                }
            }
        };

        println!(
            "{} Resolved active interface: {}",
            "OK".bright_green().bold(),
            iface.name.bright_cyan().bold()
        );
        println!(
            "     IP: {}  |  Netmask: {}  |  Gateway: {} ({})\n",
            iface.ip.to_string().bright_white(),
            iface.netmask.to_string().bright_white(),
            iface.gateway.to_string().bright_white(),
            iface.gateway_mac.to_string().bright_white()
        );

        RustrictCli::new(iface)
    };

    // Apply startup flags if provided
    if args.iter().any(|a| a == "--strict") {
        app.set_strict_mode(true);
        println!(
            "{} Strict mode explicitly enabled by CLI flag.",
            "[SCOPE]".bright_yellow().bold()
        );
    } else if args.iter().any(|a| a == "--permissive") {
        app.set_strict_mode(false);
        println!(
            "{} Permissive LAN mode explicitly enabled by CLI flag.",
            "[SCOPE]".bright_green().bold()
        );
    }

    for (i, arg) in args.iter().enumerate() {
        if (arg == "--blockmode" || arg == "-b") && i + 1 < args.len() {
            let mode_str = args[i + 1].to_lowercase();
            if mode_str == "mitm" || mode_str == "kernel" {
                app.set_spoofer_mode(rustrict::spoofer::SpooferMode::Mitm);
            } else if mode_str == "blackhole" || mode_str == "l2" {
                app.set_spoofer_mode(rustrict::spoofer::SpooferMode::Blackhole);
            }
        }
    }

    // 3. Start interactive REPL
    app.run_interactive();

    // 4. Cleanup on normal exit
    if !is_router_lab && !is_offline {
        let report = platform::cleanup_forwarding();
        if !report.is_success() {
            for (iface_name, err) in &report.failed_interfaces {
                eprintln!(
                    "{} Failed to restore forwarding on interface '{}': {}",
                    "[ERR]".bright_red().bold(),
                    iface_name,
                    err
                );
            }
            eprintln!(
                "{} Operator intervention required: Run 'Get-NetIPInterface -InterfaceAlias <name>' to verify/restore interface state.",
                "[WARN]".yellow().bold()
            );
            std::process::exit(1);
        }
    }
}
