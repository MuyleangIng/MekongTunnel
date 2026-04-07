#!/usr/bin/env sh
# install.sh — Mekong Tunnel CLI installer for macOS and Linux
# Usage: curl -fsSL https://mekongtunnel.dev/install.sh | sh
# Or:    sh install.sh [--version v1.4.9] [--dir /usr/local/bin]
set -eu

# ── Defaults ─────────────────────────────────────────────────────────────────
REPO="MuyleangIng/MekongTunnel"
VERSION=""          # empty = fetch latest from GitHub
INSTALL_DIR=""      # empty = auto-detect

# ── Colors ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD="\033[1m"; CYAN="\033[36m"; GREEN="\033[32m"
  YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
else
  BOLD=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

info()    { printf "  ${CYAN}→${RESET}  %s\n" "$1"; }
ok()      { printf "  ${GREEN}✔${RESET}  %s\n" "$1"; }
warn()    { printf "  ${YELLOW}!${RESET}  %s\n" "$1"; }
die()     { printf "  ${RED}✖${RESET}  %s\n" "$1" >&2; exit 1; }
banner()  { printf "\n${BOLD}%s${RESET}\n\n" "$1"; }

# ── Parse args ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version|-v) VERSION="$2"; shift 2 ;;
    --dir|-d)     INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: install.sh [--version v1.4.9] [--dir /usr/local/bin]"
      exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

# ── Detect OS + arch ──────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS_NAME="darwin" ;;
  Linux)  OS_NAME="linux"  ;;
  *) die "Unsupported OS: $OS. Use install.ps1 for Windows." ;;
esac

case "$ARCH" in
  arm64|aarch64) ARCH_NAME="arm64" ;;
  x86_64|amd64)  ARCH_NAME="amd64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

BINARY="mekong-${OS_NAME}-${ARCH_NAME}"
PLATFORM_LABEL="${OS_NAME}/${ARCH_NAME}"

banner "Mekong Tunnel — CLI Installer"
info "Platform: ${PLATFORM_LABEL}"

# ── Resolve version ───────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
  info "Fetching latest version from GitHub..."
  if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  else
    die "curl or wget is required."
  fi
  [ -n "$LATEST" ] || die "Could not determine latest version."
  VERSION="$LATEST"
fi

ok "Version: ${VERSION}"

# ── Resolve install dir ───────────────────────────────────────────────────────
if [ -z "$INSTALL_DIR" ]; then
  if [ "$OS_NAME" = "darwin" ]; then
    # macOS: always /usr/local/bin so VS Code, npm, pip SDKs can find mekong
    # without shell PATH tricks. Sudo is requested below if needed.
    INSTALL_DIR="/usr/local/bin"
  elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  elif [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

DEST="${INSTALL_DIR}/mekong"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

info "Installing to: ${DEST}"

# ── Download ──────────────────────────────────────────────────────────────────
TMP_FILE="$(mktemp /tmp/mekong.XXXXXX)"
trap 'rm -f "$TMP_FILE"' EXIT

info "Downloading ${BINARY}..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --progress-bar "$URL" -o "$TMP_FILE" || die "Download failed. Check your internet connection."
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_FILE" "$URL" || die "Download failed. Check your internet connection."
else
  die "curl or wget is required to download mekong."
fi

# ── Verify file size (basic check) ────────────────────────────────────────────
FILE_SIZE=$(wc -c < "$TMP_FILE" | tr -d ' ')
if [ "$FILE_SIZE" -lt 1000000 ]; then
  die "Downloaded file is too small (${FILE_SIZE} bytes). The URL may be wrong or the release may not exist."
fi

# ── Install ───────────────────────────────────────────────────────────────────
install_binary() {
  local dest="$1"
  local dir
  dir="$(dirname "$dest")"
  if [ -w "$dir" ]; then
    cp "$TMP_FILE" "$dest"
    chmod +x "$dest"
    return 0
  fi
  # Need elevated write — only use sudo when we have an interactive TTY
  if [ -t 0 ] || [ -t 1 ]; then
    info "Requesting sudo for install to ${dir}..."
    sudo cp "$TMP_FILE" "$dest" && sudo chmod +x "$dest" && return 0
  fi
  return 1
}

if ! install_binary "$DEST"; then
  # No interactive TTY (piped curl) and /usr/local/bin not writable.
  # Fall back to ~/.local/bin and give a one-liner to promote later.
  FALLBACK_DIR="$HOME/.local/bin"
  mkdir -p "$FALLBACK_DIR"
  DEST="${FALLBACK_DIR}/mekong"
  cp "$TMP_FILE" "$DEST"
  chmod +x "$DEST"
  warn "Installed to ${DEST} (sudo unavailable in pipe)"
  warn "To make VS Code + SDKs find mekong without PATH tricks, run:"
  warn "  sudo mv ${DEST} /usr/local/bin/mekong"
fi

# ── macOS: remove Gatekeeper quarantine ──────────────────────────────────────
if [ "$OS_NAME" = "darwin" ]; then
  info "Removing macOS quarantine flag..."
  if [ -w "$DEST" ]; then
    xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
  else
    sudo xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
  fi
  ok "Gatekeeper quarantine removed"
fi

# ── Add to PATH hint ──────────────────────────────────────────────────────────
SHELL_NAME="$(basename "${SHELL:-sh}")"
RC_FILE=""
case "$SHELL_NAME" in
  zsh)  RC_FILE="$HOME/.zshrc" ;;
  bash) RC_FILE="$HOME/.bashrc" ;;
  fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
esac

IN_PATH=false
echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR" && IN_PATH=true

if [ "$IN_PATH" = false ] && [ -n "$RC_FILE" ]; then
  PATH_LINE="export PATH=\"\$PATH:${INSTALL_DIR}\""
  [ "$SHELL_NAME" = "fish" ] && PATH_LINE="fish_add_path ${INSTALL_DIR}"
  echo "" >> "$RC_FILE"
  echo "# Added by mekong installer" >> "$RC_FILE"
  echo "$PATH_LINE" >> "$RC_FILE"
  export PATH="$PATH:$INSTALL_DIR"
  warn "Added ${INSTALL_DIR} to PATH in ${RC_FILE}"
  warn "Run: source ${RC_FILE}  (or open a new terminal)"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
if "$DEST" version >/dev/null 2>&1 || "$DEST" --help >/dev/null 2>&1; then
  ok "mekong installed successfully!"
else
  warn "Binary installed but verification failed — try: ${DEST} version"
fi

# ── Shell completion ───────────────────────────────────────────────────────────
install_completion() {
  local rc_file="$1"
  local shell_type="$2"

  # Skip if not a real file or if completion already installed
  [ -f "$rc_file" ] || touch "$rc_file"
  if grep -q "mekong completion" "$rc_file" 2>/dev/null; then
    ok "Tab completion already set up in ${rc_file}"
    return
  fi

  # Append completion block guarded so it won't break non-interactive shells
  {
    printf '\n# mekong tab completion (added by installer)\n'
    printf 'if command -v mekong >/dev/null 2>&1; then\n'
    printf '  eval "$(mekong completion %s 2>/dev/null)"\n' "$shell_type"
    printf 'fi\n'
  } >> "$rc_file"
  ok "Tab completion added to ${rc_file}"
  info "Run: source ${rc_file}  (or open a new terminal)"
}

case "$SHELL_NAME" in
  zsh)  install_completion "$HOME/.zshrc" "zsh" ;;
  bash)
    if [ "$OS_NAME" = "darwin" ]; then
      install_completion "$HOME/.bash_profile" "bash"
    else
      install_completion "$HOME/.bashrc" "bash"
    fi
    ;;
  fish)
    info "Fish completion: run  mekong completion fish  (not yet supported, use zsh/bash)" ;;
  *)
    info "Tab completion: run  mekong completion zsh >> ~/.zshrc && source ~/.zshrc" ;;
esac

# ── Done ─────────────────────────────────────────────────────────────────────
printf "\n${BOLD}  Ready!${RESET} Run:\n\n"
printf "  ${CYAN}mekong login${RESET}       — sign in for a reserved subdomain\n"
printf "  ${CYAN}mekong 3000${RESET}        — expose localhost:3000 to the internet\n"
printf "  ${CYAN}mekong test${RESET}        — verify your setup\n\n"
