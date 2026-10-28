# Rustrict Safety & Operational Rules of Engagement

> ⚠️ **IMPORTANT NOTICE:** ARP cache poisoning, bandwidth throttling, and network packet dropping directly alter network behavior. Rustrict must **ONLY** be deployed on networks, subnets, and host endpoints where you have explicit, documented authorization from the network owner. Unauthorized disruption of network communications is unlawful.

---

## 1. Safety Architecture Overview

Rustrict is engineered with defense-in-depth safety layers designed to prevent operator accidents, network partition storms, and self-lockouts:

```text
               Target Action Request (limit / block / simulate / ports)
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │    1. Target Admission & Exclusions   │
                   │  - Is target Controller (self) IP/MAC?│───► [REJECT: Self-Protection]
                   │  - Is target Gateway IP/MAC?          │───► [REJECT: Gateway Protection]
                   │  - Is target in excluded_ips/macs?    │───► [REJECT: User Excluded]
                   └───────────────────────────────────────┘
                                       │ (Passed)
                                       ▼
                   ┌───────────────────────────────────────┐
                   │       2. Scope Boundary Check         │
                   │  - If Strict: Must match allowed_cidr │───► [REJECT: Out of Authorized CIDR]
                   │  - If Permissive: Must be RFC 1918 /  │───► [REJECT: Internet IP Prohibited]
                   │    local subnet (No public WAN routing)
                   └───────────────────────────────────────┘
                                       │ (Passed)
                                       ▼
                   ┌───────────────────────────────────────┐
                   │      3. Enforcement Execution         │
                   │  - Dynamic spoofer status sync        │
                   │  - WinDivert kernel rule installation │
                   │  - Fail-closed driver validation      │
                   └───────────────────────────────────────┘
```

---

## 2. Permissive vs. Strict Scope Modes

### Permissive Mode (Default)
- **Active when:** `strict_mode: false` (default on startup).
- **Behavior:** All RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`) and the current local interface subnet are allowed.
- **Safety Boundary:** Arbitrary Internet IP addresses (such as `8.8.8.8` or `1.1.1.1`) are strictly rejected. You cannot accidentally direct ARP poisoning or gateway spoofing at public Internet targets.
- **Controller/Gateway Safety:** The host machine running Rustrict (controller) and the default gateway IP/MAC remain strictly excluded from blocking.

### Strict Mode
- **Active when:** Explicitly enabled via `scope strict on` (or `scope on`).
- **Behavior:** Enforcement is **strictly confined** to the CIDR prefixes registered in `scope status` (e.g. `192.168.1.0/24`). Any target address outside these authorized prefixes is immediately rejected with an admission error.
- **Use Cases:** Multi-VLAN corporate labs, authorized penetration tests with rigid rules of engagement, and shared campus testbeds.

---

## 3. Scope Management Commands

Rustrict provides rich, convenient commands for regulating authorized operational boundaries:

| Command | Effect |
| :--- | :--- |
| `scope status` | Displays current mode (Strict / Permissive), allowed CIDRs, and excluded IPs/MACs. |
| `scope add all` / `scope all` | Authorizes all standard private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). |
| `scope add <cidr/ip>` | Adds a specific CIDR or single IP to authorized scope. E.g. `scope add 192.168.1.0` (auto `/24`) or `scope add 192.168.36.84` (auto `/32`). |
| `scope remove <cidr>` | Removes a CIDR prefix from the authorized scope list. |
| `scope exclude-ip <ip>` | Explicitly protects an IP from being blocked, limited, or probed. |
| `scope exclude-mac <mac>` | Explicitly protects a physical MAC address from interception. |
| `scope reset` | Resets allowed scope back to the active adapter's local subnet. |
| `scope clear` | Clears all user-defined CIDRs and exclusions. |
| `scope on` / `scope off` | Quick toggle for strict boundary enforcement. |

---

## 4. Protected Invariants (Cannot Be Overridden)

1. **Controller Self-Lockout Prevention:**
   The IPv4 and MAC address of the interface running Rustrict are permanently excluded from target admission. Rustrict will refuse to throttle or blackhole its own host adapter.

2. **Default Gateway Protection in Normal Mode:**
   The default gateway IP and MAC cannot be added as a blocked victim. In normal operation, traffic flows between the victim and the gateway *through* the controller; blackholing the gateway itself would disrupt all network hosts simultaneously.

3. **Subnet Network & Broadcast Rejection:**
   Network addresses (e.g. `.0` on `/24`) and directed broadcast addresses (e.g. `.255` on `/24`) are blocked from single-host targeting to avoid broadcast storms.

4. **Zero-Probe Router-Lab Startup:**
   When running `rustrict.exe --router-lab`, startup uses a dedicated read-only operating system query. It executes **zero** `SendARP` requests, **zero** ICMP ping packets, and **zero** raw Ethernet frame transmissions. The gateway is never probed on launch without explicit operator instructions.

5. **Fail-Closed Persistence:**
   If saved state in `rustrict_state.json` contains malformed, corrupted, or out-of-scope targets, Rustrict validates every entry against current adapter boundaries before re-arming. Out-of-scope rules are quarantined rather than blindly applied.

---

## 5. Emergency Recovery & Clean Shutdown

### In-App Clean Release:
- Use `free all` (or `unblock all`) to immediately remove all active throttling rules and stop ARP poisoning.
- Typing `exit` or `quit` automatically:
  1. Stops the packet interception and rate-limiting threads.
  2. Sends **3 bursts of authentic ARP replies** to every poisoned host and the gateway to restore true MAC tables.
  3. Closes WinDivert kernel handles.
  4. Restores original Windows IP forwarding settings.

### Manual / Out-of-Band Recovery:
If Rustrict is terminated abnormally (e.g., hard system crash or task killed via `taskkill /f`):
1. **Network Self-Healing:** Standard ARP cache entries expire and refresh automatically within 15–45 seconds on modern operating systems (RFC 1122 / RFC 4861).
2. **Clear Persisted Rules:** If you wish to wipe any saved blocks before restarting:
   ```powershell
   Remove-Item -Force "$env:ProgramData\Rustrict\rustrict_state.json"
   ```
3. **Flush Host ARP Cache:**
   ```powershell
   netsh interface ip delete arpcache
   ```
