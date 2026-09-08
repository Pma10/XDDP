#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
make test
python3 tests/gate_integration.py --binary gate/target/release/xddp-gate
python3 tests/gate_integration.py --binary gate/target/release/xddp-gate --proxy-v2
python3 tests/gate_resilience_integration.py --binary gate/target/release/xddp-gate
if [ "${XDDP_BPF_TEST:-0}" = 1 ]; then
    python3 -m unittest discover -s tests -p test_xdp.py -v
else
    echo 'BPF verifier/test-run: NOT EXECUTED (run XDDP_BPF_TEST=1 as root).'
fi
