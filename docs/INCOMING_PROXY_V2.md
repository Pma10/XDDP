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

## Diagnosing connections without packet dumps

The gate exports counters on its configured, loopback-only metrics address
(default `127.0.0.1:9109`):

```sh
curl -fsS http://127.0.0.1:9109/metrics | grep proxy_v2_ingress
```

- `proxy_v2_ingress_accepted`: valid v2 header from a trusted peer;
  the Gate accepted the asserted original player address for further policy.
- `proxy_v2_ingress_untrusted`: the TCP peer was not in trusted CIDRs.
  Check the **source IP as seen by the origin**, not the TCPShield player-facing IP.
- `proxy_v2_ingress_invalid`: wrong/malformed header, or unexpected
  connection closure during parsing; check that TCPShield has **v2** enabled,
  not plain Minecraft traffic or v1 PROXY.
- `proxy_v2_ingress_timeout`: the proxy did not deliver the complete
  bounded header in time.

An increasing `accepted` counter does **not** guarantee Leaf login:
the backend may still reject its own outgoing PROXY header, wrong Minecraft
protocol, or an unrelated login policy. Check Leaf logs and
`config/paper-global.yml` `proxies.proxy-protocol: true` for a direct Paper
backend. Gate startup's `observation=true` can reflect the initial runtime
policy before the controller publishes its state; don't confuse it with
PROXY v2 receive mode.

## Installer and rollback

Run the script only in a maintenance window and only after the backend
is configured to accept an incoming PROXY header:

```sh
curl -fsSL https://raw.githubusercontent.com/Pma10/XDDP/feature/trusted-inbound-proxy-v2-20261029/scripts/install-incoming-proxy-v2.sh -o /tmp/xddp-install-proxy-v2.sh
sudo env LEAF_PROXY_READY=YES sh /tmp/xddp-install-proxy-v2.sh
```

The installer compiles/tests the branch, bootstraps Cargo when absent,
**preserves an existing nonempty trusted CIDR list**, and backs up the Gate
binary and configuration in `/root/xddp-proxy-backup.*`. On a failed
deployment it attempts an atomic rollback and restarts only the Gate.
It never edits `/etc/xddp/controller.json`, XDP maps, Leaf configuration,
the firewall, or TCPShield's panel settings.

If incompatible, restore the saved binary and gate.json and restart only
`xddp-gate`. No need to detach XDP or restart the controller.

**Security:** A test configuration containing both `0.0.0.0/1` and
`128.0.0.0/1` trusts the entire IPv4 Internet. It is equivalent to
disabling incoming source authentication, and allows arbitrary client-IP
spoofing. It is not a substitute for the origin firewall. Restore actual
TCPShield egress CIDRs before exposing a public listener.

For NGINX Proxy Manager, ordinary NGINX `proxy_protocol on` sends **v1**
unless specifically configured otherwise; this patch is v2 only. Test the
actual wire format or use TCPShield's v2 mode.
