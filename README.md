# XDDP

Residual DDoS mitigation for an upstream-scrubbed Minecraft Java server:
native XDP on eth0, a bounded Rust admission gate, and a leased adaptive controller.

**Development in progress. Do not deploy this revision to production.**
Default policies observe; rate thresholds require production measurements.
See [design and threat model](docs/DESIGN.md). Build instructions, test evidence,
deployment and rollback procedures will accompany the implementation.
