use colored::*;
use rustrict::cli::{print_banner, RustrictCli};
use rustrict::platform;

fn main() {
    print_banner("2.0.0");

    // 1. Check Windows Administrator privileges
    if !platform::is_privileged() {
        eprintln!(
            "{} Please run as Administrator (open PowerShell or Command Prompt as Administrator).",
            "[ERR]".bright_red().bold()
        );
        std::process::exit(1);
    }

    // 2. Discover default network interface and gateway
    let iface = match platform::get_default_interface() {
        Ok(iface) => iface,
        Err(e) => {
            eprintln!("{} Failed to resolve network interface: {}", "[ERR]".bright_red().bold(), e);
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

    // 3. Enable IP forwarding
    if let Err(e) = platform::enable_ip_forwarding() {
        eprintln!("{} Warning: Could not enable IP forwarding: {}", "[WARN]".yellow().bold(), e);
    }

    // 4. Start interactive REPL
    let mut app = RustrictCli::new(iface);
    app.run_interactive();

    // 5. Cleanup on normal exit
    let _ = platform::disable_ip_forwarding();
}
