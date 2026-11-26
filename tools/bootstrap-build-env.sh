#!/usr/bin/env bash
# Run inside the dedicated Linux Lume guest; never install build tools on macOS.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'Run this script inside the Linux build sandbox.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential cmake ninja-build ccache git curl wget unzip xz-utils \
    flex bison gperf pkg-config python3 python3-pip python3-venv libffi-dev libssl-dev libusb-1.0-0-dev dfu-util nodejs ca-certificates libsodium-dev python3-cryptography
IDF_DIR="${IDF_DIR:-/opt/esp-idf}"
if [[ ! -f "$IDF_DIR/export.sh" ]]; then
    sudo mkdir -p "$(dirname "$IDF_DIR")"
    sudo install -d -o "$(id -u)" -g "$(id -g)" "$IDF_DIR"
    git clone --depth 1 --branch v5.5.3 https://github.com/espressif/esp-idf.git "$IDF_DIR"
fi
actual="$(git -C "$IDF_DIR" describe --tags --exact-match)"
[[ "$actual" == v5.5.3 ]] || { echo "Expected ESP-IDF v5.5.3; found $actual" >&2; exit 1; }
# Resume interrupted downloads without replacing an existing checkout.
for attempt in 1 2 3; do
    if git -C "$IDF_DIR" submodule update --init --recursive --depth 1 --jobs 4; then break; fi
    [[ "$attempt" != 3 ]] || exit 1
done
IDF_GITHUB_ASSETS="${IDF_GITHUB_ASSETS:-dl.espressif.com/github_assets}" "$IDF_DIR/install.sh" esp32c3
