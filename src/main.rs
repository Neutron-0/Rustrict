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

    print_banner("2.0.0");

    // 1. Run Pre-flight Environment Diagnostics
    let env_status = platform::check_environment();
    if !env_status.is_admin {
        eprintln!(
            "{} Please run as Administrator (open PowerShell or Command Prompt as Administrator).",
            "[ERR]".bright_red().bold()
        );
        std::process::exit(1);
    }

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

    // 2. Discover default network interface and gateway
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

    // 3. Start interactive REPL
    let mut app = RustrictCli::new(iface);
    app.run_interactive();

    // 4. Cleanup on normal exit
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
