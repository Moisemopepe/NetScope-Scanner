from __future__ import annotations

import re
import socket
import ssl
import subprocess  # nosec B404
from dataclasses import replace
from shutil import which

from config.ports import get_port_info
from scanner.models import ServiceFingerprint

MAX_BANNER_BYTES = 2048


PRODUCT_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"OpenSSH[_/ ](?P<version>[\w.\-p]+)", re.IGNORECASE), "OpenBSD", "OpenSSH"),
    (re.compile(r"Apache(?:/| )(?P<version>[\w.\-]+)", re.IGNORECASE), "Apache", "Apache HTTP Server"),
    (re.compile(r"nginx(?:/| )(?P<version>[\w.\-]+)", re.IGNORECASE), "F5", "nginx"),
    (re.compile(r"Microsoft-IIS/(?P<version>[\w.\-]+)", re.IGNORECASE), "Microsoft", "IIS"),
    (re.compile(r"vsftpd (?P<version>[\w.\-]+)", re.IGNORECASE), "vsftpd", "vsftpd"),
    (re.compile(r"Postfix", re.IGNORECASE), "Postfix", "Postfix"),
    (re.compile(r"Exim (?P<version>[\w.\-]+)", re.IGNORECASE), "Exim", "Exim"),
    (re.compile(r"MySQL(?: Server)? (?P<version>[\w.\-]+)", re.IGNORECASE), "Oracle", "MySQL"),
    (re.compile(r"PostgreSQL (?P<version>[\w.\-]+)", re.IGNORECASE), "PostgreSQL", "PostgreSQL"),
]


def normalize_for_cpe(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip().lower())
    return cleaned.strip("_")


def build_cpe(vendor: str, product: str, version: str) -> str:
    if not vendor or not product:
        return ""
    cpe_version = version or "*"
    return f"cpe:2.3:a:{normalize_for_cpe(vendor)}:{normalize_for_cpe(product)}:{normalize_for_cpe(cpe_version)}:*:*:*:*:*:*:*"


def infer_confidence(product: str, version: str, cpe: str) -> str:
    if product and version and cpe and "*" not in cpe.split(":")[5]:
        return "Confirmé"
    if product and version:
        return "Probable"
    if product:
        return "Possible"
    return "Information insuffisante"


def parse_banner(service: str, banner: str) -> ServiceFingerprint:
    vendor = ""
    product = ""
    version = ""
    probable_os = ""
    for pattern, found_vendor, found_product in PRODUCT_PATTERNS:
        match = pattern.search(banner)
        if match:
            vendor = found_vendor
            product = found_product
            version = match.groupdict().get("version", "") or ""
            os_match = re.search(r"Ubuntu|Debian|Windows|FreeBSD|OpenBSD|CentOS|Red Hat", banner, re.IGNORECASE)
            probable_os = os_match.group(0) if os_match else ""
            break
    cpe = build_cpe(vendor, product, version)
    return ServiceFingerprint(
        protocol="tcp",
        vendor=vendor,
        product=product,
        version=version,
        probable_os=probable_os,
        banner=banner[:MAX_BANNER_BYTES],
        cpe=cpe,
        confidence=infer_confidence(product, version, cpe),
    )


class ServiceDetector:
    def __init__(self, timeout: float = 0.8, max_banner_bytes: int = MAX_BANNER_BYTES, use_nmap: bool = False) -> None:
        self.timeout = timeout
        self.max_banner_bytes = max_banner_bytes
        self.use_nmap = use_nmap and which("nmap") is not None

    def detect(self, host: str, port: int) -> ServiceFingerprint:
        info = get_port_info(port)
        if self.use_nmap:
            nmap_fp = self._detect_with_nmap(host, port)
            if nmap_fp.product:
                return nmap_fp
        if port in {80, 8080}:
            return self._detect_http(host, port, tls=False)
        if port in {443, 8443}:
            return self._detect_http(host, port, tls=True)
        if port in {22, 21, 25, 110, 143}:
            banner = self._read_banner(host, port)
            return self._with_service_fallback(parse_banner(info.service, banner), info.service)
        if port in {445, 139}:
            return ServiceFingerprint(protocol="tcp", product="SMB", vendor="Microsoft", banner="Détection SMB sans authentification", cpe=build_cpe("Microsoft", "SMB", ""), confidence="Possible")
        return ServiceFingerprint(protocol="tcp", banner=self._read_banner(host, port), confidence="Information insuffisante")

    def _with_service_fallback(self, fp: ServiceFingerprint, service: str) -> ServiceFingerprint:
        if fp.product:
            return fp
        return replace(fp, product=service if service else "", confidence="Possible" if service else "Information insuffisante")

    def _read_banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    data = sock.recv(self.max_banner_bytes)
                except TimeoutError:
                    return ""
                return data.decode("utf-8", errors="replace").strip()
        except OSError:
            return ""

    def _detect_http(self, host: str, port: int, tls: bool) -> ServiceFingerprint:
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetScopeScanner/2.1\r\nConnection: close\r\n\r\n".encode()
        banner = ""
        probable_os = ""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                raw.settimeout(self.timeout)
                sock: socket.socket | ssl.SSLSocket = raw
                if tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(raw, server_hostname=host)
                    cert = sock.getpeercert()
                    if cert:
                        probable_os = "Certificat TLS disponible"
                sock.sendall(request)
                banner = sock.recv(self.max_banner_bytes).decode("utf-8", errors="replace")
        except OSError:
            banner = ""
        fp = parse_banner("HTTPS" if tls else "HTTP", banner)
        return replace(fp, protocol="https" if tls else "http", probable_os=fp.probable_os or probable_os)

    def _detect_with_nmap(self, host: str, port: int) -> ServiceFingerprint:
        try:
            completed = subprocess.run(  # nosec B603 B607
                ["nmap", "-sV", "--version-light", "-Pn", "-p", str(port), host],
                capture_output=True,
                text=True,
                timeout=max(8, self.timeout * 8),
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ServiceFingerprint()
        output = completed.stdout[: self.max_banner_bytes]
        fp = parse_banner("", output)
        return replace(fp, banner=output)
