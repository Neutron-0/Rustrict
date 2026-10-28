use colored::*;
use rustrict::cli::{print_banner, RustrictCli};
use rustrict::platform;

fn main() {
    platform::enable_ansi_support();

    // Check for standalone CLI commands (e.g. read-only NIC diagnostics)
    // Dispatched before environment checks, interface resolution, or SendARP.
    let args: Vec<String> = std::env::args().collect();
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

    print_banner("2.0.1");

    let is_router_lab = args.iter().any(|a| a == "--router-lab");

    // 1. Run Pre-flight Environment Diagnostics
    let env_status = if is_router_lab {
        platform::check_router_lab_environment()
    } else {
        platform::check_environment()
    };
    if !is_router_lab && !env_status.is_admin {
        eprintln!(
            "{} Please run as Administrator (open PowerShell or Command Prompt as Administrator).",
            "[ERR]".bright_red().bold()
        );
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

    // 2. Discover default network interface and gateway
    let mut app = if is_router_lab {
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
        let iface = match platform::get_default_interface() {
            Ok(iface) => iface,
            Err(e) => {
                eprintln!(
                    "{} Failed to resolve network interface: {}",
                    "[ERR]".bright_red().bold(),
                    e
                );
                std::process::exit(1);
            }
        };

        println!(
            "{} Resolved default interface: {}",
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

    // 3. Start interactive REPL
    app.run_interactive();

    // 4. Cleanup on normal exit
    if !is_router_lab {
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
