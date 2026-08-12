from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ServiceFingerprint:
    protocol: str = "tcp"
    vendor: str = ""
    product: str = ""
    version: str = ""
    probable_os: str = ""
    banner: str = ""
    cpe: str = ""
    confidence: str = "Information insuffisante"


@dataclass(frozen=True)
class CveFinding:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    vector: str
    cwe: str
    published: str
    last_modified: str
    references: list[str] = field(default_factory=list)
    affected_versions: str = ""
    kev: bool = False
    recommendation: str = ""
    confidence: str = "Information insuffisante"


@dataclass(frozen=True)
class NetworkInterfaceInfo:
    name: str
    ipv4: str
    netmask: str
    cidr: str
    mac: str = "Non disponible"
    gateway: str = "Non disponible"
    is_up: bool = True


@dataclass(frozen=True)
class DiscoveredDevice:
    ip: str
    status: str
    latency_ms: float | None = None
    hostname: str = "Non disponible"
    mac: str = "Non disponible"
    vendor: str = "Inconnu"
    discovery_method: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    probable_os: str = ""
    last_seen: str = ""
    cve_count: int = 0
    risk: str = "FAIBLE"


@dataclass(frozen=True)
class ScanFinding:
    ip: str
    hostname: str
    mac: str
    port: int
    service: str
    state: str
    risk: str
    description: str
    recommendation: str
    fingerprint: ServiceFingerprint = field(default_factory=ServiceFingerprint)
    cves: list[CveFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanSummary:
    target: str
    duration_seconds: float
    host_count: int
    open_port_count: int
    critical_count: int
    threat_count: int
    findings: list[ScanFinding]

    @property
    def cve_count(self) -> int:
        return sum(len(finding.cves) for finding in self.findings)

    @property
    def critical_cve_count(self) -> int:
        return sum(1 for finding in self.findings for cve in finding.cves if cve.severity.upper() == "CRITICAL")

    @property
    def kev_count(self) -> int:
        return sum(1 for finding in self.findings for cve in finding.cves if cve.kev)

    @property
    def services_without_version(self) -> int:
        return sum(1 for finding in self.findings if finding.service and not finding.fingerprint.version)
