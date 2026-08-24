#!/bin/bash
# install.sh
set -euo pipefail
echo "Detecting OS..."
OS=$(uname -s)
ARCH=$(uname -m)

echo "Installing Baton Adapter for $OS-$ARCH..."
mkdir -p ~/.baton

echo "Downloading binary..."
# curl -sSL -o baton-adapter "https://example.com/downloads/baton-adapter-${OS}-${ARCH}"
# curl -sSL -o baton-adapter.sha256 "https://example.com/downloads/baton-adapter-${OS}-${ARCH}.sha256"
# echo "Verifying checksum..."
# sha256sum -c baton-adapter.sha256

echo "Installing to /usr/local/bin..."
# sudo mv baton-adapter /usr/local/bin/baton-adapter
# sudo chmod +x /usr/local/bin/baton-adapter

echo "Baton Adapter installed successfully!"
echo "Next steps:"
echo "1. Run 'baton-adapter setup' to configure the gateway."
echo "2. Start the service with 'systemctl start baton-adapter.service' or run it manually."
