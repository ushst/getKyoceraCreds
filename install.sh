#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "    $*"; }

echo "===== CVE-2022-1026 Kyocera installer ====="

# Python deps
echo
echo "[*] Python зависимости..."
if command -v pip3 &>/dev/null; then
    pip3 install --quiet requests xmltodict
    ok "requests, xmltodict установлены"
elif command -v pip &>/dev/null; then
    pip install --quiet requests xmltodict
    ok "requests, xmltodict установлены"
else
    warn "pip не найден — установи вручную: pip3 install requests xmltodict"
fi

# MSF symlink
echo
echo "[*] Metasploit module..."
SYMLINK="$SCRIPT_DIR/auxiliary/gather/kyocera_address_book.rb"
if [ ! -e "$SYMLINK" ]; then
    mkdir -p "$SCRIPT_DIR/auxiliary/gather"
    ln -sf "$SCRIPT_DIR/kyocera_address_book.rb" "$SYMLINK"
    ok "симлинк создан: auxiliary/gather/kyocera_address_book.rb"
else
    ok "симлинк уже существует"
fi

# chmod scripts
chmod +x "$SCRIPT_DIR"/*.sh
ok "права на запуск установлены для *.sh"

# tool checks
echo
echo "[*] Проверка инструментов..."
command -v python3    &>/dev/null && ok "python3"     || warn "python3 не найден"
command -v msfconsole &>/dev/null && ok "msfconsole"  || warn "msfconsole не найден  — https://metasploit.com"
command -v nuclei     &>/dev/null && ok "nuclei"      || warn "nuclei не найден      — https://github.com/projectdiscovery/nuclei"

echo
echo "===== Готово ====="
info "./run_python.sh  10.0.0.10"
info "./run_msf.sh     10.0.0.10"
info "./run_nuclei.sh  10.0.0.10"
