from __future__ import annotations

from scanner.service_detection import build_cpe, infer_confidence, parse_banner


def test_parse_ssh_banner_extracts_product_version_and_cpe() -> None:
    fp = parse_banner("SSH", "SSH-2.0-OpenSSH_9.2p1 Debian-2")
    assert fp.product == "OpenSSH"
    assert fp.version == "9.2p1"
    assert fp.cpe.startswith("cpe:2.3:a:openbsd:openssh:9.2p1")
    assert fp.confidence == "Confirmé"


def test_parse_http_server_banner() -> None:
    fp = parse_banner("HTTP", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
    assert fp.product == "nginx"
    assert fp.version == "1.24.0"


def test_cpe_generation_normalizes_names() -> None:
    assert build_cpe("Apache", "Apache HTTP Server", "2.4.58") == "cpe:2.3:a:apache:apache_http_server:2.4.58:*:*:*:*:*:*:*"


def test_confidence_never_confirmed_without_version() -> None:
    assert infer_confidence("SMB", "", "cpe:2.3:a:microsoft:smb:*:*:*:*:*:*:*:*") == "Possible"
