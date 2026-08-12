from __future__ import annotations

import concurrent.futures
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from config.ports import get_port_info
from scanner.models import ScanFinding, ScanSummary
from scanner.network import get_mac_address, resolve_hostname
from scanner.service_detection import ServiceDetector
from scanner.validation import parse_ip_list, parse_target
from vulnerability.cve_matcher import CveMatcher

ProgressCallback = Callable[[int, int, str], None]
FindingCallback = Callable[[ScanFinding], None]
EventCallback = Callable[[str, dict[str, object]], None]


@dataclass(frozen=True)
class ScannerSettings:
    connect_timeout: float = 0.6
    banner_timeout: float = 0.8
    max_workers: int = 96
    enable_nmap: bool = False
    enable_cve_lookup: bool = True


class NetworkScanner:
    def __init__(
        self,
        timeout: float = 0.6,
        max_workers: int = 96,
        settings: ScannerSettings | None = None,
        service_detector: ServiceDetector | None = None,
        cve_matcher: CveMatcher | None = None,
    ) -> None:
        self.settings = settings or ScannerSettings(connect_timeout=timeout, max_workers=max_workers)
        self.timeout = self.settings.connect_timeout
        self.max_workers = self.settings.max_workers
        self.service_detector = service_detector or ServiceDetector(timeout=self.settings.banner_timeout, use_nmap=self.settings.enable_nmap)
        self.cve_matcher = cve_matcher or CveMatcher(enabled=self.settings.enable_cve_lookup)
        self._stop_event = threading.Event()
        self._logger = logging.getLogger(__name__)

    def stop(self) -> None:
        self._stop_event.set()

    def reset(self) -> None:
        self._stop_event.clear()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def scan(
        self,
        target: str,
        ports: Iterable[int],
        on_progress: ProgressCallback | None = None,
        on_finding: FindingCallback | None = None,
        on_event: EventCallback | None = None,
    ) -> ScanSummary:
        self.reset()
        started = time.perf_counter()
        plan = parse_ip_list(target) if "," in target or ";" in target else parse_target(target)
        port_list = sorted({int(port) for port in ports})
        total = len(plan.hosts) * len(port_list)
        completed = 0
        findings: list[ScanFinding] = []
        host_cache: dict[str, tuple[str, str]] = {}
        if on_event:
            on_event("scan_started", {"target": target, "hosts": len(plan.hosts), "ports": len(port_list), "total": total})

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        future_map: dict[concurrent.futures.Future[bool], tuple[str, int]] = {}
        job_iter = ((host, port) for host in plan.hosts for port in port_list)
        max_in_flight = max(self.max_workers * 4, self.max_workers)
        try:
            self._fill_futures(executor, future_map, job_iter, max_in_flight)
            while future_map:
                if self.stopped:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                done_futures, _pending = concurrent.futures.wait(
                    future_map,
                    timeout=0.2,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done_futures:
                    continue
                for future in done_futures:
                    host, port = future_map.pop(future)
                    completed += 1
                    try:
                        is_open = future.result()
                    except Exception:
                        self._logger.exception("Erreur pendant le scan de %s:%s", host, port)
                        is_open = False
                    if is_open:
                        finding = self._build_finding(host, port, host_cache, on_event)
                        findings.append(finding)
                        if on_finding:
                            on_finding(finding)
                    if on_progress:
                        on_progress(completed, total, host)
                self._fill_futures(executor, future_map, job_iter, max_in_flight)
        finally:
            executor.shutdown(wait=not self.stopped, cancel_futures=self.stopped)

        duration = time.perf_counter() - started
        if on_event:
            on_event("scan_stopped" if self.stopped else "scan_completed", {"duration": duration, "findings": len(findings)})
        hosts = {finding.ip for finding in findings}
        critical = sum(1 for finding in findings if finding.risk == "CRITIQUE")
        threats = sum(1 for finding in findings if finding.risk in {"CRITIQUE", "ÉLEVÉ"})
        return ScanSummary(
            target=target,
            duration_seconds=duration,
            host_count=len(hosts),
            open_port_count=len(findings),
            critical_count=critical,
            threat_count=threats,
            findings=sorted(findings, key=lambda item: (item.ip, item.port)),
        )

    def _build_finding(
        self,
        host: str,
        port: int,
        host_cache: dict[str, tuple[str, str]],
        on_event: EventCallback | None,
    ) -> ScanFinding:
        hostname, mac = host_cache.setdefault(host, (resolve_hostname(host), get_mac_address(host)))
        info = get_port_info(port)
        if on_event:
            on_event("port_open", {"host": host, "port": port, "service": info.service})
        fingerprint = self.service_detector.detect(host, port)
        if on_event:
            on_event("service_detected", {"host": host, "port": port, "product": fingerprint.product, "version": fingerprint.version})
            if fingerprint.product:
                on_event("cve_lookup", {"host": host, "port": port, "product": fingerprint.product, "version": fingerprint.version})
        try:
            cves = self.cve_matcher.match(fingerprint)
        except Exception:
            self._logger.exception("Erreur récupérable pendant la recherche CVE de %s:%s", host, port)
            cves = []
        return ScanFinding(
            ip=host,
            hostname=hostname,
            mac=mac,
            port=port,
            service=info.service,
            state="OUVERT",
            risk=info.risk,
            description=info.description,
            recommendation=info.recommendation,
            fingerprint=fingerprint,
            cves=cves,
        )

    def _fill_futures(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        future_map: dict[concurrent.futures.Future[bool], tuple[str, int]],
        job_iter: Iterable[tuple[str, int]],
        max_in_flight: int,
    ) -> None:
        while len(future_map) < max_in_flight and not self.stopped:
            try:
                host, port = next(job_iter)  # type: ignore[arg-type]
            except StopIteration:
                return
            future_map[executor.submit(self._scan_port, host, port)] = (host, port)

    def _scan_port(self, host: str, port: int) -> bool:
        if self.stopped:
            return False
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except (TimeoutError, OSError):
            return False
