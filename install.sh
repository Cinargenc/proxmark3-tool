#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  proxmark3-tool — One-line installer
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/Cinargenc/proxmark3-tool/main/install.sh | bash
#
# ─────────────────────────────────────────────────────────────────────────────

set -e

REPO="https://github.com/Cinargenc/proxmark3-tool"
DEST="$HOME/proxmark3-tool"

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[0m'; BOLD='\033[1m'

banner() {
  echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════╗"
  echo -e "║   proxmark3-tool  installer          ║"
  echo -e "╚══════════════════════════════════════╝${RESET}\n"
}

check_dep() {
  if ! command -v "$1" &>/dev/null; then
    echo -e "${RED}[✗] '$1' not found. Please install it and re-run.${RESET}"
    exit 1
  fi
}

banner

# ── Requirements ──────────────────────────────────────────────────────────────
check_dep python3
check_dep git

echo -e "${CYAN}[+] Python  : $(python3 --version)${RESET}"
echo -e "${CYAN}[+] Git     : $(git --version)${RESET}\n"

# ── Clone / update ────────────────────────────────────────────────────────────
if [ -d "$DEST/.git" ]; then
  echo -e "${CYAN}[*] Existing install found — pulling latest…${RESET}"
  git -C "$DEST" pull --ff-only
else
  echo -e "${CYAN}[*] Cloning into $DEST …${RESET}"
  git clone "$REPO" "$DEST"
fi

# ── Optional: create alias ────────────────────────────────────────────────────
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then SHELL_RC="$HOME/.zshrc"
fi

ALIAS_LINE="alias pm3tool='python3 $DEST/main.py'"
if [ -n "$SHELL_RC" ] && ! grep -q "pm3tool" "$SHELL_RC"; then
  echo "$ALIAS_LINE" >> "$SHELL_RC"
  echo -e "${GREEN}[✓] Alias 'pm3tool' added to $SHELL_RC${RESET}"
  echo -e "    Restart your shell or run: ${CYAN}source $SHELL_RC${RESET}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}[✓] Installation complete!${RESET}\n"
echo -e "  cd $DEST"
echo -e "  python3 main.py samples/mifare_classic_1k.txt\n"
