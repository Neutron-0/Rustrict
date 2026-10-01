# Security Policy

## What this tool does

Rustrict sends ARP packets, intercepts forwarded traffic with WinDivert, and
probes hosts (ports, TLS, SMB). On networks you do not own or have written
permission to test, that can be illegal and disruptive. Only run it on your
own network or a lab with clear permission.

## Supported versions

| Version | Supported |
| :--- | :---: |
| 2.0.x | Yes |
| < 2.0 | No |

## Reporting a vulnerability

Do not open a public issue for a security bug. Contact the maintainer
directly:

- GitHub: [Neutron-0](https://github.com/Neutron-0)
- Include: version (`rustrict --version` or Cargo.toml), Windows build,
  steps to reproduce, and impact.

Expect a first reply within 7 days. Fixes ship as a patch release with a
CHANGELOG entry. Please allow time to fix before any public disclosure
(90 days is appreciated).

## Scope rules built into the tool

- `scope` command: allow-list CIDRs, exclude IPs/MACs, strict mode.
- `free` command and clean exit restore real ARP entries.
- Blocks persist in `rustrict_state.json` (local file, never sent anywhere).

## Safe testing checklist

1. Use a lab subnet, not a shared office network.
2. Exclude the gateway and your own machine from targets.
3. Start with `limit`, not `block`. Verify with `hosts` first.
4. Keep a second terminal ready with `free all` in case you lock yourself out.
