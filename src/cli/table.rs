use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use crate::types::{Host, HostStatus};

pub fn render_hosts_table(hosts: &[Host]) {
    if hosts.is_empty() {
        println!("No hosts discovered yet. Run 'scan' to discover devices.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("ID").fg(Color::Cyan),
            Cell::new("IP-Address").fg(Color::Cyan),
            Cell::new("MAC-Address").fg(Color::Cyan),
            Cell::new("Hostname").fg(Color::Cyan),
            Cell::new("Vendor / Hardware").fg(Color::Cyan),
            Cell::new("State").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
        ]);

    for host in hosts {
        let state_cell = if host.online {
            Cell::new("Online").fg(Color::Green)
        } else {
            Cell::new("Offline").fg(Color::DarkGrey)
        };

        let status_cell = match host.status {
            HostStatus::Free => Cell::new("Free").fg(Color::Green),
            HostStatus::Limited(rate, dir) => {
                Cell::new(format!("Limited ({} {})", rate, dir.pretty())).fg(Color::Yellow)
            }
            HostStatus::Blocked(dir) => {
                if host.persistent_block {
                    Cell::new(format!("Blocked [P] ({})", dir.pretty())).fg(Color::Red)
                } else {
                    Cell::new(format!("Blocked ({})", dir.pretty())).fg(Color::Red)
                }
            }
        };

        let hostname_str = if host.name.is_empty() {
            "-".to_string()
        } else {
            host.name.clone()
        };

        let vendor_str = if host.vendor.is_empty() || host.vendor == "Unknown" {
            "-".to_string()
        } else {
            host.vendor.clone()
        };

        table.add_row(Row::from(vec![
            Cell::new(host.id.to_string()),
            Cell::new(host.ip.to_string()),
            Cell::new(host.mac.to_string()),
            Cell::new(hostname_str),
            Cell::new(vendor_str),
            state_cell,
            status_cell,
        ]));
    }

    println!("{table}");
}
