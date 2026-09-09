use colored::*;

pub fn print_banner(_version: &str) {
    let line1 = "  ██████╗  ██╗   ██╗ ███████╗ ████████╗ ██████╗  ██╗  ██████╗ ████████╗";
    let line2 = "  ██╔══██╗ ██║   ██║ ██╔════╝ ╚══██╔══╝ ██╔══██╗ ██║ ██╔════╝ ╚══██╔══╝";
    let line3 = "  ██████╔╝ ██║   ██║ ███████╗    ██║    ██████╔╝ ██║ ██║         ██║   ";
    let line4 = "  ██╔══██╗ ██║   ██║ ╚════██║    ██║    ██╔══██╗ ██║ ██║         ██║   ";
    let line5 = "  ██║  ██║ ╚██████╔╝ ███████║    ██║    ██║  ██║ ██║ ╚██████╗    ██║   ";
    let line6 = "  ╚═╝  ╚═╝  ╚═════╝  ╚══════╝    ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═════╝    ╚═╝   ";

    println!();
    println!("{}", line1.bright_red().bold());
    println!("{}", line2.bright_red().bold());
    println!("{}", line3.bright_red().bold());
    println!("{}", line4.bright_red().bold());
    println!("{}", line5.bright_red().bold());
    println!("{}", line6.bright_red().bold());
    println!(
        "          {}\n",
        "Windows Network Bandwidth Limiter & Controller".bright_cyan().bold()
    );
}
