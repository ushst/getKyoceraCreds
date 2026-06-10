#!/usr/bin/env bash
# Запускает Nuclei-шаблон CVE-2022-1026 против одного хоста или списка IP.
# Использование: ./run_nuclei.sh <IP | FILE> [доп. флаги nuclei]
#   ./run_nuclei.sh 10.0.0.10
#   ./run_nuclei.sh ips.txt
#   ./run_nuclei.sh 10.0.0.10 -o result.json -json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/CVE-2022-1026.yaml"

if [ $# -eq 0 ]; then
    echo "Использование: $0 <IP | FILE> [nuclei флаги]"
    echo ""
    echo "  $0 10.0.0.10"
    echo "  $0 ips.txt"
    echo "  $0 ips.txt -o results.json -json"
    echo ""
    echo "  Формат файла ips.txt: один IP в строке (порт указывать не нужно)"
    exit 1
fi

if ! command -v nuclei &>/dev/null; then
    echo "[!] nuclei не найден."
    echo "    Установи: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "    Или скачай: https://github.com/projectdiscovery/nuclei/releases"
    exit 1
fi

TARGET="$1"
shift

if [ -f "$TARGET" ]; then
    # Файл со списком IP — добавляем схему и порт к каждому адресу
    TMPFILE=$(mktemp)
    trap 'rm -f "$TMPFILE"' EXIT
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line//,/ }"
        for ip in $line; do
            [ -z "$ip" ] || [[ "$ip" == \#* ]] && continue
            # Если уже содержит https:// — оставляем как есть
            if [[ "$ip" == https://* ]]; then
                echo "$ip"
            else
                echo "https://$ip:9091"
            fi
        done
    done < "$TARGET" > "$TMPFILE"

    echo "[*] Запускаем nuclei по списку из $TARGET ($(wc -l < "$TMPFILE") хостов)..."
    nuclei -t "$TEMPLATE" -l "$TMPFILE" "$@"
else
    # Одиночный IP
    HOST="$TARGET"
    [[ "$HOST" == https://* ]] || HOST="https://$HOST:9091"
    echo "[*] Запускаем nuclei против $HOST..."
    nuclei -t "$TEMPLATE" -u "$HOST" "$@"
fi
