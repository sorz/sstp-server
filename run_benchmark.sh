#! /usr/bin/env nix-shell
#! nix-shell -i bash -p python3 uv sstp iperf3 ppp iproute2

# Run iperf3 benchmark (./test/benchmark.py) with nix-shell and sudo

set -e

if [ "$EUID" -ne 0 ]; then
    # Non-root
    uv sync
    uv pip install -e .

    echo "Elevating privileges to run benchmark..."
    exec sudo -E env PATH="$PATH" bash "$0" "$@"
else
    echo "Running benchmark as root..."
    uv run ./tests/benchmark.py "$@"
fi
