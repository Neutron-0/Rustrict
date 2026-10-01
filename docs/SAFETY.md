# Safety

Read this before running Rustrict on anything but your own lab.

## Only your network

ARP spoofing and packet dropping disrupt real users. Only target networks
you own or have written permission to test. Shared offices, dorms, and
public Wi-Fi are out.

## Stay in scope

```text
rustrict > scope add 192.168.1.0/24
rustrict > scope strict on
rustrict > scope status
```

- Exclude the gateway and infrastructure before any `limit all`.
- Strict mode rejects out-of-range targets instead of acting on them.

## Know how to undo

- `free <target>` removes limits/blocks and sends real ARP replies.
- `quit` stops spoofing, stops WinDivert, disables IP forwarding.
- Blocks persist in `rustrict_state.json`. Delete or `free` entries there
  if a device should stay unblocked after restart. The file never leaves
  your machine.

## Start small

1. `scan`, then `hosts`. Confirm IDs before acting.
2. `limit` one host first. Watch it. Then decide on `block`.
3. Keep a second admin terminal open with `free all` ready.
