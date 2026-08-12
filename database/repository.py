from __future__ import annotations

import json
import shutil
import sqlite3
import time
from pathlib import Path

from scanner.models import CveFinding, ScanFinding, ScanSummary, ServiceFingerprint


class ScanRepository:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or Path.home() / "NetScope Scanner" / "netscope.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            current = self._schema_version(conn)
            if current == 0 and self.db_path.exists() and self.db_path.stat().st_size > 0:
                self._backup_database()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    target TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    host_count INTEGER NOT NULL,
                    open_port_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    threat_count INTEGER NOT NULL,
                    findings_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    product TEXT,
                    version TEXT,
                    cpe TEXT,
                    confidence TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    cvss_score REAL,
                    severity TEXT,
                    cwe TEXT,
                    kev INTEGER NOT NULL DEFAULT 0,
                    confidence TEXT,
                    published TEXT,
                    last_modified TEXT,
                    description TEXT,
                    recommendation TEXT,
                    UNIQUE(service_id, cve_id),
                    FOREIGN KEY(service_id) REFERENCES scan_services(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_services_scan ON scan_services(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_services_cpe ON scan_services(cpe)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_cves_cve ON scan_cves(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_cves_kev ON scan_cves(kev)")
            conn.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)")

    def _schema_version(self, conn: sqlite3.Connection) -> int:
        try:
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            return int(row[0] or 0)
        except sqlite3.Error:
            return 0

    def _backup_database(self) -> None:
        backup = self.db_path.with_suffix(f".backup-{int(time.time())}.db")
        try:
            shutil.copy2(self.db_path, backup)
        except OSError:
            pass

    def save_scan(self, summary: ScanSummary) -> int:
        payload = json.dumps([finding.to_dict() for finding in summary.findings], ensure_ascii=False)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (target, duration_seconds, host_count, open_port_count, critical_count, threat_count, findings_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.target,
                    summary.duration_seconds,
                    summary.host_count,
                    summary.open_port_count,
                    summary.critical_count,
                    summary.threat_count,
                    payload,
                ),
            )
            scan_id = int(cursor.lastrowid)
            self._save_service_rows(conn, scan_id, summary)
            return scan_id

    def _save_service_rows(self, conn: sqlite3.Connection, scan_id: int, summary: ScanSummary) -> None:
        for finding in summary.findings:
            service_cursor = conn.execute(
                """
                INSERT INTO scan_services (scan_id, ip, port, service, product, version, cpe, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.ip,
                    finding.port,
                    finding.service,
                    finding.fingerprint.product,
                    finding.fingerprint.version,
                    finding.fingerprint.cpe,
                    finding.fingerprint.confidence,
                ),
            )
            service_id = int(service_cursor.lastrowid)
            for cve in finding.cves:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO scan_cves
                    (service_id, cve_id, cvss_score, severity, cwe, kev, confidence, published, last_modified, description, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        service_id,
                        cve.cve_id,
                        cve.cvss_score,
                        cve.severity,
                        cve.cwe,
                        1 if cve.kev else 0,
                        cve.confidence,
                        cve.published,
                        cve.last_modified,
                        cve.description,
                        cve.recommendation,
                    ),
                )

    def list_scans(self) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, target, duration_seconds, host_count, open_port_count, critical_count, threat_count FROM scans ORDER BY id DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_scan(self, scan_id: int) -> ScanSummary:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise ValueError("Scan introuvable.")
        findings = [_finding_from_dict(item) for item in json.loads(row["findings_json"])]
        return ScanSummary(
            target=row["target"],
            duration_seconds=row["duration_seconds"],
            host_count=row["host_count"],
            open_port_count=row["open_port_count"],
            critical_count=row["critical_count"],
            threat_count=row["threat_count"],
            findings=findings,
        )

    def delete_scan(self, scan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def _finding_from_dict(item: dict) -> ScanFinding:
    fingerprint_data = item.pop("fingerprint", {}) or {}
    cve_data = item.pop("cves", []) or []
    return ScanFinding(
        **item,
        fingerprint=ServiceFingerprint(**fingerprint_data),
        cves=[CveFinding(**cve) for cve in cve_data],
    )
