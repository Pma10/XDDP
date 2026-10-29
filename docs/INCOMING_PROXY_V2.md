# Trusted incoming PROXY v2 (TCPShield → XDDP → Leaf)

The gate can now optionally consume PROXY protocol **v2** on ingress, before
Minecraft framing. It uses the asserted original source IP for the Rust Gate's
per-IP and per-prefix admission, allow/block rules, and downstream PROXY v2
header. The XDP filter runs before the TCP connection, so it still sees the
**TCPShield proxy IP**, not the original player IP. Never claim per-player XDP
rate limiting from this feature.

## Required trust boundary

- The PROXY v2 header is **not authenticated**. Accept connections **only**
  from verified TCPShield IP ranges; enforce this again with your cloud/network
  firewall. In-gate CIDR checks do not replace a firewall.
- TCPShield supplies its public IP ranges at https://tcpshield.com/v4/ and
  https://tcpshield.com/v4-cf/. Check the lists at deployment and periodically.
  Treat additions and removals as controlled configuration changes; do not trust
  arbitrary client-supplied proxy headers.
- Incoming PROXY is mandatory when enabled. Direct users without the header
  are rejected. v1 and the TCPShield signed-handshake plugin are **not**
  compatible with this mode. TCPShield panel Backend Set must enable PROXY v2.
- The proxy's underlying TCP peer identity is checked before interpreting any
  client-provided address. The version/command and TCP family are validated;
  headers are fully read within a bounded deadline and 4096-byte payload cap.
  LOCAL/UDP/UNSPEC and malformed/short headers fail closed.
- The destination in the trusted proxy header is used as the outgoing PROXY v2
  destination to preserve the address family. TLVs are ignored.
- A copied TCP connection must not bypass IP ACLs or per-IP limits: the Gate
  now admits each connection **after** extracting the trusted original IP.

## Config (gate.json)

Add the following new field, keeping all your existing limits:

```json
"incoming_proxy_v2": {
  "enabled": true,
  "trusted_proxies": ["198.178.119.0/24", "104.234.6.0/25"]
},
"proxy_v2": true,
"allow_backend_identity_loss": false
```

The CIDRs above are an example snapshot, **not a permanent list**. Fill them
from TCPShield's official range feeds and include any required Cloudflare
ranges. The new field is optional for existing configurations and defaults off.

## Back end

For a direct Leaf/Paper backend, enable proxy protocol ingestion on the Leaf
listener (usually the Paper global configuration under `proxies.proxy-protocol`,
verify the exact Leaf version). Allow only the XDDP gate to connect to the Java
backend port (example 25566), and remove TCPShield RealIP plugin when using the
PROXY protocol mode. If behind Velocity, configure PROXY on Velocity's private
listener instead and retain Velocity's authenticated forwarding to Leaf.

Production migration requires a maintenance window: replacing the XDDP Gate
binary and restarting `xddp-gate` disconnects active sessions. Back up the
existing binary and `/etc/xddp/gate.json`; validate the new Gate's config and
TCPShield reachability before moving player DNS.

## Check & rollback

```bash
sudo /usr/local/bin/xddp-gate /etc/xddp/gate.json --check
sudo systemctl status xddp-gate --no-pager
sudo ss -lntp | grep -E '25565|25566'
sudo ddosctl status
```

If incompatible, restore the saved binary and gate.json and restart only
`xddp-gate`. No need to detach XDP or restart the controller.

For NGINX Proxy Manager, ordinary NGINX `proxy_protocol on` sends **v1**
unless specifically configured otherwise; this patch is v2 only. Test the
actual wire format or use TCPShield's v2 mode.
