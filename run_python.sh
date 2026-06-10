#!/usr/bin/env bash
# Обёртка для getKyoceraCreds.py
# Использование: ./run_python.sh [args...]
#   ./run_python.sh 10.0.0.10
#   ./run_python.sh 10.0.0.10,10.0.0.20 -i 10.0.0.30
#   ./run_python.sh -f ips.txt -o result.txt

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -eq 0 ]; then
    echo "Использование: $0 <IP | FILE> [IP,...] [-i IP] [-o OUTPUT]"
    echo ""
    echo "  $0 10.0.0.10"
    echo "  $0 10.0.0.10,10.0.0.20"
    echo "  $0 ips.txt"
    echo "  $0 ips.txt -o result.txt"
    exit 1
fi

# Если первый аргумент — существующий файл, передаём его через -f
if [ -f "$1" ] && [[ "$1" != -* ]]; then
    FILE="$1"; shift
    python3 "$SCRIPT_DIR/getKyoceraCreds.py" -f "$FILE" "$@"
else
    python3 "$SCRIPT_DIR/getKyoceraCreds.py" "$@"
fi
