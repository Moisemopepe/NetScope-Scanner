from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortRisk:
    port: int
    service: str
    risk: str
    description: str
    recommendation: str


PORT_RISKS: dict[int, PortRisk] = {
    20: PortRisk(20, "FTP-DATA", "ÉLEVÉ", "Canal de données FTP souvent associé à des échanges non chiffrés.", "Limiter l'exposition FTP et privilégier SFTP ou FTPS."),
    21: PortRisk(21, "FTP", "ÉLEVÉ", "FTP peut transmettre des identifiants et données en clair.", "Utiliser SFTP/FTPS, restreindre les accès et surveiller les connexions."),
    22: PortRisk(22, "SSH", "FAIBLE", "SSH est chiffré mais reste une porte d'administration sensible.", "Utiliser des clés, MFA si possible, et désactiver les connexions inutiles."),
    23: PortRisk(23, "Telnet", "CRITIQUE", "Telnet transmet les communications sans chiffrement.", "Désactiver Telnet et remplacer par SSH."),
    25: PortRisk(25, "SMTP", "MOYEN", "SMTP exposé peut être mal configuré ou abusé comme relais.", "Vérifier le relais, SPF/DKIM/DMARC et restreindre l'accès."),
    53: PortRisk(53, "DNS", "MOYEN", "DNS exposé peut divulguer des informations ou permettre des abus.", "Désactiver la récursion publique et limiter les transferts de zone."),
    80: PortRisk(80, "HTTP", "MOYEN", "HTTP n'offre pas de chiffrement pour les données sensibles.", "Rediriger vers HTTPS et durcir les en-têtes de sécurité."),
    110: PortRisk(110, "POP3", "MOYEN", "POP3 non protégé peut exposer des messages ou identifiants.", "Privilégier POP3S/IMAPS et désactiver les versions non chiffrées."),
    135: PortRisk(135, "RPC", "ÉLEVÉ", "RPC exposé augmente la surface d'attaque Windows.", "Limiter au réseau interne et filtrer par pare-feu."),
    139: PortRisk(139, "NetBIOS", "MOYEN", "NetBIOS peut exposer des informations de partage Windows.", "Restreindre aux segments nécessaires ou désactiver si inutile."),
    143: PortRisk(143, "IMAP", "MOYEN", "IMAP non chiffré peut exposer des informations sensibles.", "Utiliser IMAPS et imposer TLS."),
    443: PortRisk(443, "HTTPS", "FAIBLE", "HTTPS indique un transport chiffré sans garantir la sécurité applicative.", "Vérifier les certificats, TLS et correctifs applicatifs."),
    445: PortRisk(445, "SMB", "ÉLEVÉ", "SMB exposé est une cible fréquente pour mouvements latéraux et rançongiciels.", "Limiter strictement SMB, patcher Windows et désactiver SMBv1."),
    1433: PortRisk(1433, "MSSQL", "ÉLEVÉ", "Base SQL Server accessible sur le réseau.", "Restreindre l'accès, imposer TLS et comptes à privilèges minimaux."),
    3306: PortRisk(3306, "MySQL", "ÉLEVÉ", "Base MySQL accessible sur le réseau.", "Limiter par pare-feu, durcir les comptes et activer TLS."),
    3389: PortRisk(3389, "RDP", "ÉLEVÉ", "RDP exposé est une cible d'attaque très courante.", "Utiliser VPN, NLA, MFA et règles de verrouillage."),
    5432: PortRisk(5432, "PostgreSQL", "ÉLEVÉ", "Base PostgreSQL accessible sur le réseau.", "Limiter les sources, durcir pg_hba.conf et activer TLS."),
    5900: PortRisk(5900, "VNC", "ÉLEVÉ", "VNC expose souvent un accès bureau à distance.", "Limiter au VPN et imposer une authentification forte."),
    8080: PortRisk(8080, "HTTP alt.", "MOYEN", "Port web alternatif pouvant héberger une console ou application.", "Inventorier l'application et protéger l'accès administratif."),
    8443: PortRisk(8443, "HTTPS alt.", "FAIBLE", "Port HTTPS alternatif souvent utilisé par des consoles d'administration.", "Vérifier TLS, authentification et exposition réseau."),
}

FAST_PORTS = [22, 80, 443, 445, 3389]
STANDARD_PORTS = list(PORT_RISKS)
MAX_PREFIXLEN = 24


def get_port_info(port: int) -> PortRisk:
    return PORT_RISKS.get(
        port,
        PortRisk(port, f"TCP/{port}", "FAIBLE", "Service TCP détecté.", "Vérifier que ce service est attendu et correctement maintenu."),
    )
