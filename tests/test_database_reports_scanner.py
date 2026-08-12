from __future__ import annotations

import socket
import threading
from pathlib import Path

from database.repository import ScanRepository
from reports.exporters import export_csv, export_excel, export_pdf
from scanner.engine import NetworkScanner
from scanner.models import ScanFinding, ScanSummary


def sample_summary() -> ScanSummary:
    finding = ScanFinding(
        ip="127.0.0.1",
        hostname="localhost",
        mac="Non disponible",
        port=443,
        service="HTTPS",
        state="OUVERT",
        risk="FAIBLE",
        description="Test",
        recommendation="Tester",
    )
    return ScanSummary("127.0.0.1", 0.2, 1, 1, 0, 0, [finding])


def test_sqlite_save_and_read(tmp_path: Path) -> None:
    repo = ScanRepository(tmp_path / "scans.db")
    scan_id = repo.save_scan(sample_summary())
    loaded = repo.get_scan(scan_id)
    assert loaded.target == "127.0.0.1"
    assert loaded.findings[0].service == "HTTPS"
    repo.delete_scan(scan_id)
    assert repo.list_scans() == []


def test_sqlite_schema_migration_table_exists(tmp_path: Path) -> None:
    repo = ScanRepository(tmp_path / "scans.db")
    with repo._connect() as conn:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    assert row[0] == 1


def test_exports_create_files(tmp_path: Path) -> None:
    summary = sample_summary()
    pdf = export_pdf(summary, tmp_path / "rapport.pdf")
    xlsx = export_excel(summary, tmp_path / "rapport.xlsx")
    csv = export_csv(summary, tmp_path / "rapport.csv")
    assert pdf.exists() and pdf.stat().st_size > 0
    assert xlsx.exists() and xlsx.stat().st_size > 0
    assert csv.exists() and csv.read_text(encoding="utf-8-sig").startswith("Adresse IP")


def test_scanner_finds_local_temporary_server() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept_once() -> None:
        server.settimeout(2)
        try:
            conn, _addr = server.accept()
            conn.close()
        finally:
            stop.set()
            server.close()

    thread = threading.Thread(target=accept_once)
    thread.start()
    scanner = NetworkScanner(timeout=0.3, max_workers=4)
    summary = scanner.scan("127.0.0.1", [port])
    thread.join(timeout=2)
    assert stop.is_set()
    assert summary.open_port_count == 1
    assert summary.findings[0].port == port


def test_scanner_stop_flag() -> None:
    scanner = NetworkScanner(timeout=0.01, max_workers=2)
    scanner.stop()
    assert scanner.stopped
    scanner.reset()
    assert not scanner.stopped
