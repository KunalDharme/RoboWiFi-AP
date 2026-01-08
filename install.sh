#!/usr/bin/env bash
# install.sh - Dependency installer for Rogue AP Detector
# Supports: Debian/Ubuntu, Arch, Fedora/RHEL
# Run as root: sudo ./install.sh

set -e

echo "=============================================="
echo " Rogue AP Detector - Dependency Installer"
echo "=============================================="
echo

# Root check
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Please run as root (sudo ./install.sh)"
  exit 1
fi

# Detect OS
if [[ -f /etc/debian_version ]]; then
  OS="debian"
elif [[ -f /etc/arch-release ]]; then
  OS="arch"
elif [[ -f /etc/redhat-release ]]; then
  OS="redhat"
else
  echo "[ERROR] Unsupported Linux distribution"
  exit 1
fi

echo "[INFO] Detected OS: $OS"
echo

# ==============================
# PACKAGE LISTS
# ==============================

REQUIRED_PKGS=(
  iw
  wireless-tools
)

RECOMMENDED_PKGS=(
  aircrack-ng
  tcpdump
  tshark
  arpwatch
  jq
  curl
  notify-send
  mailutils
)

OPTIONAL_PKGS=(
  p0f
)

# ==============================
# INSTALL FUNCTIONS
# ==============================

install_debian() {
  apt update
  apt install -y "${REQUIRED_PKGS[@]}" "${RECOMMENDED_PKGS[@]}" "${OPTIONAL_PKGS[@]}"
}

install_arch() {
  pacman -Sy --noconfirm "${REQUIRED_PKGS[@]}" "${RECOMMENDED_PKGS[@]}" "${OPTIONAL_PKGS[@]}"
}

install_redhat() {
  dnf install -y epel-release || true
  dnf install -y "${REQUIRED_PKGS[@]}" "${RECOMMENDED_PKGS[@]}" "${OPTIONAL_PKGS[@]}"
}

# ==============================
# INSTALL
# ==============================

echo "[INFO] Installing dependencies..."
case "$OS" in
  debian) install_debian ;;
  arch) install_arch ;;
  redhat) install_redhat ;;
esac

echo
echo "[INFO] Verifying installations..."
echo

# ==============================
# VERIFY
# ==============================

CHECK_CMDS=(
  iw
  iwconfig
  tcpdump
  tshark
  airmon-ng
  jq
  curl
)

for cmd in "${CHECK_CMDS[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[ OK ] $cmd"
  else
    echo "[WARN] $cmd not found"
  fi
done

echo
echo "=============================================="
echo " Installation Complete"
echo "=============================================="
echo
echo "You can now run:"
echo "  sudo ./rogue_ap_detector.sh --help"
echo
echo "⚠️  Use only on networks you own or are authorized to test."
