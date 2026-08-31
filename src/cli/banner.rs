use colored::*;

pub fn print_banner(version: &str) {
    let banner = r#"
██████╗ ██╗   ██╗███████╗████████╗██████╗ ██╗ ██████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ██████╔╝██║██║        ██║   
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██║██║        ██║   
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║╚██████╗   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝   ╚═╝   
             Windows Network Bandwidth Limiter & Controller"#;

    println!("{}", banner.bright_red());
    println!(
        "                                     v{} [Rust Core]\n",
        version.bright_white().bold()
    );
}
