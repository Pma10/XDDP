"""Serialize validated static policy for the loader; no I/O or map mutations."""

MAX_POLICY_BYTES = 4 * 1024 * 1024
PORT_FLAGS = (
    ("protected_tcp_ports", 1),
    ("drop_tcp_ports", 2),
    ("drop_udp_ports", 4),
)
PREFIX_MARKER = 1
BOGON_REASON = 5
MANUAL_BLOCK_REASON = 11


def loader_policy(cfg):
    ports = {}
    for name, flag in PORT_FLAGS:
        for port in cfg[name]:
            ports[port] = ports.get(port, 0) | flag
    lines = [f"port {port} {flags}" for port, flags in sorted(ports.items())]

    blocks = dict.fromkeys(cfg["bogon_prefixes"], BOGON_REASON)
    blocks.update(dict.fromkeys(cfg["block_prefixes"], MANUAL_BLOCK_REASON))
    maps = (
        ("owned", dict.fromkeys(cfg["owned_prefixes"], PREFIX_MARKER)),
        ("allow", dict.fromkeys(cfg["allow_prefixes"], PREFIX_MARKER)),
        ("block", blocks),
    )
    for name, prefixes in maps:
        lines.extend(f"{name} {prefix} {reason}" for prefix, reason in sorted(prefixes.items()))

    document = "\n".join(lines) + "\n"
    if len(document.encode("ascii")) > MAX_POLICY_BYTES:
        raise ValueError("loader policy exceeds 4 MiB")
    return document
