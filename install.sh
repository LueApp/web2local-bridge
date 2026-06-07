#!/usr/bin/env bash
# web2local — quick installer for Linux
set -e

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy daemon
cp "$SCRIPT_DIR/daemon.py" "$INSTALL_DIR/web2local"
chmod +x "$INSTALL_DIR/web2local"

# Insert shebang if needed
if ! head -1 "$INSTALL_DIR/web2local" | grep -q python; then
  sed -i '1s|^|#!/usr/bin/env python3\n|' "$INSTALL_DIR/web2local"
fi

# Create default config
CONFIG_DIR="$HOME/.config/web2local"
mkdir -p "$CONFIG_DIR"
CONFIG="$CONFIG_DIR/config.json"
if [ ! -f "$CONFIG" ]; then
  cat > "$CONFIG" <<'EOF'
{
  "port": 7878,
  "whitelist": [],
  "graylist": []
}
EOF
  echo "Created config at $CONFIG"
fi

# Check PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo ""
  echo "  Add this to your ~/.bashrc or ~/.zshrc:"
  echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Installed: $INSTALL_DIR/web2local"
echo "Run:       web2local"
