from __future__ import annotations

from scanner.engine import NetworkScanner
from scanner.models import CveFinding, ServiceFingerprint


class FakeDetector:
    def detect(self, host: str, port: int) -> ServiceFingerprint:
        return ServiceFingerprint(vendor="OpenBSD", product="OpenSSH", version="9.2p1", cpe="cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*", confidence="Confirmé")


class FakeMatcher:
    def match(self, fingerprint: ServiceFingerprint) -> list[CveFinding]:
        return [
            CveFinding(
                cve_id="CVE-2099-0001",
                description="Test",
                cvss_score=9.8,
                severity="CRITICAL",
                vector="",
                cwe="CWE-79",
                published="",
                last_modified="",
                kev=True,
                confidence=fingerprint.confidence,
            )
        ]


def test_scanner_realtime_events_without_ui_worker_mutation() -> None:
    scanner = NetworkScanner(service_detector=FakeDetector(), cve_matcher=FakeMatcher())
    scanner._scan_port = lambda _host, _port: True  # type: ignore[method-assign]
    events: list[str] = []
    findings = []
    summary = scanner.scan(
        "127.0.0.1",
        [22],
        on_finding=findings.append,
        on_event=lambda kind, _payload: events.append(kind),
    )
    assert summary.cve_count == 1
    assert findings[0].fingerprint.product == "OpenSSH"
    assert "port_open" in events
    assert "service_detected" in events
    assert "cve_lookup" in events


def test_scanner_handles_large_port_iterable_without_materializing_all_jobs() -> None:
    scanner = NetworkScanner(timeout=0.01, max_workers=4, service_detector=FakeDetector(), cve_matcher=FakeMatcher())
    scanner._scan_port = lambda _host, _port: False  # type: ignore[method-assign]
    progress = []
    summary = scanner.scan("127.0.0.1", range(1, 500), on_progress=lambda done, total, _host: progress.append((done, total)))
    assert summary.open_port_count == 0
    assert progress[-1] == (499, 499)
