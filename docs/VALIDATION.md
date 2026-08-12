# Validation qualité

Checklist appliquée avant livraison :

- Validation IPv4, CIDR et liste d'IP.
- Refus des plages trop grandes.
- Parsing strict des ports personnalisés.
- Découverte LAN simulée : ARP, ICMP absent mais TCP ouvert, fabricant OUI.
- Détection service/version simulée.
- CPE et CVE sur réponse NVD simulée.
- Cache CVE et expiration.
- CISA KEV simulé.
- Événements temps réel du scanner.
- Exports PDF/Excel.
- Export CSV.
- Paramètres persistants.
- Migrations SQLite versionnées.
- Smoke-test CustomTkinter.
- Build PyInstaller.

Commandes :

```powershell
python -m pytest -q
python -m compileall main.py config scanner services database reports ui vulnerability tests
pyinstaller --noconfirm --onefile --windowed --name "NetScope Scanner 2.3" main.py
```
