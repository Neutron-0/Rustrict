# Usage

Targets accept an ID, an IP, a comma list, or `all`:

```text
rustrict > block 1
rustrict > block 192.168.1.50
rustrict > block 1,2,3
rustrict > block 1,192.168.1.50,3
rustrict > block all
```

## Everyday commands

| Command | What it does |
| :--- | :--- |
| `scan` | Find hosts. `--fresh` drops offline ones. `--range 100-200` limits scope. `--ports` also scans ports. |
| `hosts` | Show table: IP, MAC, name, vendor, status. |
| `limit <t> <rate>` | Slow a target. Rate: `500kbit`, `2mbit`. Add `--upload` or `--download`, else both. |
| `block <t>` | Cut a target off. Saved to disk, re-applied on next launch. |
| `free <t>` | Undo limit/block. Restores real ARP entries. |
| `add <ip> [--mac <mac>]` | Add a device by hand. |
| `clear` | Clear screen. `quit` stops everything and exits. |

## Check and prove

| Command | What it does |
| :--- | :--- |
| `ports <t> [range]` | TCP scan. Default top 25, or custom like `80,443,8000-8080`. |
| `audit <t>` | TLS check (old SSL/TLS, weak ciphers) + SMB check (SMBv1, signing). |
| `simulate <t> [drop N] [delay MS] [jitter MS]` | Add loss/latency. `simulate <t> clear` removes it. |
| `export [markdown\|json\|sarif] [file]` | Write a report. SARIF opens in GitHub code scanning. |
| `scope ...` | `scope status`, `scope add <cidr>`, `scope strict on/off`, `scope exclude-ip/mac`. |

## Typical session

```text
rustrict > scan --fresh
rustrict > hosts
rustrict > limit 3 500kbit --download
rustrict > ports 3
rustrict > audit 3
rustrict > block 3
rustrict > free 3
rustrict > quit
```
