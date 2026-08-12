from __future__ import annotations

import logging
import queue
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path
from tkinter import TclError, filedialog, messagebox, ttk

import customtkinter as ctk

from config.ports import STANDARD_PORTS
from config.settings import (
    APP_VERSION,
    AppSettings,
    load_settings,
    recommended_settings,
    save_settings,
    validate_settings,
)
from database.repository import ScanRepository
from reports.exporters import export_csv, export_excel, export_pdf
from scanner.discovery import NetworkDiscoverer
from scanner.engine import NetworkScanner, ScannerSettings
from scanner.local_network import active_interfaces, choose_default_interface
from scanner.models import (
    DiscoveredDevice,
    NetworkInterfaceInfo,
    ScanFinding,
    ScanSummary,
)
from scanner.safety import enforce_target_policy
from scanner.validation import parse_ip_list, parse_target
from services.scan_profiles import ports_for_profile
from vulnerability.cache import VulnerabilityCache
from vulnerability.cve_matcher import CveMatcher
from vulnerability.kev_client import KevClient
from vulnerability.nvd_client import NvdClient

LOGGER = logging.getLogger(__name__)


def asset_path(relative_path: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / relative_path

COLORS = {
    "bg": "#07111F",
    "panel": "#0D1B2A",
    "panel2": "#12263A",
    "border": "#214362",
    "cyan": "#18C3E8",
    "green": "#27D17F",
    "orange": "#F5B942",
    "red": "#FF5A65",
    "text": "#F3F7FB",
    "muted": "#A8B6C8",
}

RISK_COLORS = {"CRITIQUE": COLORS["red"], "ÉLEVÉ": "#FF725E", "MOYEN": COLORS["orange"], "FAIBLE": COLORS["green"]}


class NetScopeApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("NetScope Scanner")
        self.geometry("1500x880")
        self.minsize(1220, 760)
        self.configure(fg_color=COLORS["bg"])
        self._configure_window_icon()

        self.settings = load_settings()
        self.repository = ScanRepository()
        self.scanner = self._build_scanner()
        self.discoverer = self._build_discoverer()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.findings: list[ScanFinding] = []
        self.filtered: list[ScanFinding] = []
        self.devices: list[DiscoveredDevice] = []
        self.displayed_devices: list[DiscoveredDevice] = []
        self.interfaces: list[NetworkInterfaceInfo] = []
        self.current_summary: ScanSummary | None = None
        self.scan_thread: threading.Thread | None = None
        self.scan_started_at = 0.0
        self.progress_state = {"done": 0, "total": 0, "host": "-"}
        self.activity: deque[str] = deque(maxlen=80)
        self.page = 1
        self.page_size = 12
        self.max_hosts_default = self.settings.max_hosts

        self._build_layout()
        self._refresh_history()
        self.after(self.settings.ui_refresh_ms, self._process_events)

    def _configure_window_icon(self) -> None:
        icon_file = asset_path("assets/netscope.ico")
        if icon_file.exists():
            try:
                self.iconbitmap(str(icon_file))
            except TclError as exc:
                LOGGER.debug("Unable to load window icon %s: %s", icon_file, exc)

    def _build_scanner(self) -> NetworkScanner:
        cache = VulnerabilityCache(ttl_seconds=self.settings.cve_cache_days * 24 * 3600)
        matcher = CveMatcher(
            nvd_client=NvdClient(cache=cache, retries=self.settings.retries, offline=self.settings.offline_mode),
            kev_client=KevClient(cache=cache, offline=self.settings.offline_mode),
            enabled=True,
        )
        scanner_settings = ScannerSettings(
            connect_timeout=self.settings.tcp_timeout,
            banner_timeout=self.settings.banner_timeout,
            max_workers=self.settings.max_workers,
            enable_nmap=self.settings.nmap_enabled,
            enable_cve_lookup=True,
        )
        return NetworkScanner(settings=scanner_settings, cve_matcher=matcher)

    def _build_discoverer(self) -> NetworkDiscoverer:
        return NetworkDiscoverer(timeout=self.settings.discovery_timeout, max_workers=self.settings.max_workers)

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._sidebar()
        self._main_dashboard()

    def _sidebar(self) -> None:
        side = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color="#081726")
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        ctk.CTkLabel(side, text="NetScope\nScanner", font=("Segoe UI", 25, "bold"), text_color=COLORS["text"], justify="left").pack(anchor="w", padx=28, pady=(30, 34))
        for label, active in [("Vue d'ensemble", True), ("Découverte", False), ("Équipements", False), ("Ports et services", False), ("Vulnérabilités", False), ("Ping et diagnostic", False), ("Historique", False), ("Rapports", False), ("Paramètres", False), ("À propos", False)]:
            ctk.CTkButton(
                side,
                text=label,
                anchor="w",
                height=48,
                fg_color=COLORS["panel2"] if active else "transparent",
                hover_color=COLORS["panel2"],
                text_color=COLORS["cyan"] if active else COLORS["text"],
                border_width=1 if active else 0,
                border_color=COLORS["border"],
                command=self._sidebar_action(label),
            ).pack(fill="x", padx=14, pady=6)
        status = ctk.CTkFrame(side, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1)
        status.pack(side="bottom", fill="x", padx=16, pady=16)
        ctk.CTkLabel(status, text="Statut du système", text_color=COLORS["muted"], anchor="w").pack(fill="x", padx=18, pady=(16, 6))
        ctk.CTkLabel(status, text="Protégé", text_color=COLORS["green"], font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x", padx=18)
        ctk.CTkLabel(status, text="Tous les systèmes\nopérationnels", text_color=COLORS["text"], justify="left", anchor="w").pack(fill="x", padx=18, pady=(2, 18))
        ctk.CTkLabel(status, text=f"Version {APP_VERSION}", text_color=COLORS["muted"], anchor="w").pack(fill="x", padx=18, pady=(12, 16))

    def _sidebar_action(self, label: str):
        actions = {
            "Découverte": self.start_discovery,
            "Équipements": lambda: self._switch_view("Appareils"),
            "Ports et services": lambda: self._switch_view("Ports et vulnérabilités"),
            "Vulnérabilités": lambda: self._switch_view("Ports et vulnérabilités"),
            "Ping et diagnostic": self._show_ping_help,
            "Historique": self._show_history,
            "Rapports": self._show_reports_info,
            "Paramètres": self._show_settings,
            "À propos": self._show_about,
        }
        return actions.get(label)

    def _main_dashboard(self) -> None:
        main = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew", padx=18, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        top = ctk.CTkFrame(main, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        top.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        top.grid_columnconfigure(0, weight=1)
        network_row = ctk.CTkFrame(top, fg_color="transparent")
        network_row.grid(row=0, column=0, columnspan=2, sticky="ew", padx=22, pady=(14, 2))
        network_row.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(network_row, text="Interface", text_color=COLORS["text"], font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.interface_menu = ctk.CTkOptionMenu(network_row, values=["Détection..."], width=230)
        self.interface_menu.grid(row=0, column=1, sticky="w", padx=(0, 10))
        self.target_mode = ctk.CTkOptionMenu(network_row, values=["Ma machine", "Une adresse IP", "Tout mon réseau local", "Une plage CIDR", "Liste d'adresses IP"], width=190, command=lambda _v: self._mode_changed())
        self.target_mode.set("Une plage CIDR")
        self.target_mode.grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.show_unreachable = ctk.CTkCheckBox(network_row, text="Afficher les équipements non joignables", text_color=COLORS["muted"])
        self.show_unreachable.grid(row=0, column=3, sticky="e")
        self.authorization_check = ctk.CTkCheckBox(network_row, text="Analyse autorisée", text_color=COLORS["green"])
        self.authorization_check.grid(row=0, column=4, sticky="e", padx=(12, 0))
        self._load_interfaces()

        ctk.CTkLabel(top, text="Cible IP, plage CIDR ou liste", text_color=COLORS["text"], font=("Segoe UI", 14, "bold")).grid(row=1, column=0, sticky="w", padx=22, pady=(8, 6))
        self.target_entry = ctk.CTkEntry(top, height=42, fg_color="#0A1727", border_color="#315778", text_color=COLORS["text"], font=("Segoe UI", 15))
        self.target_entry.insert(0, "192.168.1.0/24")
        self.target_entry.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 18))
        controls = ctk.CTkFrame(top, fg_color="transparent")
        controls.grid(row=1, column=1, rowspan=2, padx=18, pady=10)
        self.profile = ctk.CTkSegmentedButton(controls, values=["Ping uniquement", "Découverte rapide", "Rapide", "Standard", "Personnalisé", "Scan complet"], selected_color=COLORS["cyan"])
        self.profile.set("Standard")
        self.profile.pack(fill="x", pady=(0, 8))
        self.custom_ports = ctk.CTkEntry(controls, placeholder_text="Ports personnalisés : 22,80,443,8000-8100", width=360)
        self.custom_ports.pack(fill="x", pady=(0, 8))
        buttons = ctk.CTkFrame(controls, fg_color="transparent")
        buttons.pack(fill="x")
        ctk.CTkButton(buttons, text="Détecter mon réseau", height=40, fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=self.detect_my_network).pack(side="left", padx=(0, 6))
        ctk.CTkButton(buttons, text="Découvrir", height=40, fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=self.start_discovery).pack(side="left", padx=(0, 6))
        ctk.CTkButton(buttons, text="Lancer le scan", height=40, fg_color=COLORS["cyan"], text_color="white", font=("Segoe UI", 14, "bold"), command=self.start_scan).pack(side="left", padx=(0, 6))
        ctk.CTkButton(buttons, text="Arrêter", height=40, fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=self.stop_scan).pack(side="left", padx=(0, 6))
        ctk.CTkButton(buttons, text="Actualiser", height=40, fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=self._load_interfaces).pack(side="left")

        stats = ctk.CTkFrame(main, fg_color="transparent")
        stats.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for idx in range(8):
            stats.grid_columnconfigure(idx, weight=1)
        self.stat_vars = {key: ctk.StringVar(value="0") for key in ["hosts", "ports", "critical", "exposures", "cves", "critical_cves", "kev", "no_version"]}
        cards = [
            ("Appareils", "hosts", "Actifs", COLORS["cyan"]),
            ("Ports ouverts", "ports", f"Sur {len(STANDARD_PORTS)}", COLORS["green"]),
            ("Expositions crit.", "critical", "Ports", COLORS["orange"]),
            ("Expositions élevées", "exposures", "À vérifier", COLORS["red"]),
            ("CVE", "cves", "Potentielles", COLORS["cyan"]),
            ("CVE critiques", "critical_cves", "CVSS", COLORS["red"]),
            ("CISA KEV", "kev", "Exploitées", COLORS["orange"]),
            ("Sans version", "no_version", "À vérifier", COLORS["green"]),
        ]
        for idx, (title, key, subtitle, color) in enumerate(cards):
            self._stat_card(stats, idx, title, self.stat_vars[key], subtitle, color)

        content = ctk.CTkFrame(main, fg_color="transparent")
        content.grid(row=2, column=0, rowspan=2, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=0)
        content.grid_rowconfigure(0, weight=1)
        self._results_panel(content)
        self._right_panel(content)
        self._progress_panel(main)

    def _stat_card(self, parent: ctk.CTkFrame, column: int, title: str, var: ctk.StringVar, subtitle: str, color: str) -> None:
        card = ctk.CTkFrame(parent, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        card.grid(row=0, column=column, sticky="ew", padx=4)
        ctk.CTkLabel(card, text=title, text_color=COLORS["text"], anchor="w", font=("Segoe UI", 12, "bold")).pack(fill="x", padx=10, pady=(10, 0))
        ctk.CTkLabel(card, textvariable=var, text_color=color, font=("Segoe UI", 24, "bold")).pack(fill="x", padx=10)
        ctk.CTkLabel(card, text=subtitle, text_color=COLORS["muted"], font=("Segoe UI", 11)).pack(fill="x", padx=10, pady=(0, 10))

    def _results_panel(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(parent, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)
        header = ctk.CTkFrame(panel, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Résultats du scan", text_color=COLORS["text"], font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w")
        self.view_mode = ctk.CTkSegmentedButton(header, values=["Appareils", "Ports et vulnérabilités"], selected_color=COLORS["cyan"], command=lambda _v: self._render_current_view())
        self.view_mode.set("Ports et vulnérabilités")
        self.view_mode.grid(row=0, column=1, padx=6)
        self.search_entry = ctk.CTkEntry(header, placeholder_text="Recherche", width=190)
        self.search_entry.grid(row=0, column=2, padx=6)
        self.search_entry.bind("<KeyRelease>", lambda _event: self._apply_filters())
        self.risk_filter = ctk.CTkOptionMenu(header, values=["Tous", "CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE"], command=lambda _v: self._apply_filters(), width=120)
        self.risk_filter.set("Tous")
        self.risk_filter.grid(row=0, column=3, padx=4)
        self.cve_filter = ctk.CTkOptionMenu(header, values=["Toutes CVE", "Critique", "Élevé", "Moyen", "Faible", "CISA KEV", "Confirmé/Probable"], command=lambda _v: self._apply_filters(), width=150)
        self.cve_filter.set("Toutes CVE")
        self.cve_filter.grid(row=0, column=4, padx=4)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=COLORS["panel"], foreground=COLORS["text"], fieldbackground=COLORS["panel"], rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#0A1727", foreground=COLORS["text"], font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", COLORS["panel2"])])
        columns = ("ip", "hostname", "port", "service", "product", "version", "cves", "cvss", "kev", "confidence", "risk", "description", "recommendation")
        self.tree = ttk.Treeview(panel, columns=columns, show="headings", height=14)
        labels = ["Adresse IP", "Nom d'hôte", "Port", "Service", "Produit", "Version", "CVE", "CVSS max", "KEV", "Confiance", "Risque", "Description", "Recommandation"]
        widths = [115, 130, 60, 95, 145, 95, 80, 80, 70, 150, 90, 300, 340]
        for col, label, width in zip(columns, labels, widths):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=min(width, 80), stretch=col in {"description", "recommendation", "product"})
        self.tree.tag_configure("critical_cve", background="#3A1720")
        self.tree.tag_configure("kev", background="#3A2C12")
        self.tree.bind("<Double-1>", lambda _event: self._show_selected_detail())
        self.tree.grid(row=2, column=0, sticky="nsew", padx=(14, 0))
        vbar = ttk.Scrollbar(panel, orient="vertical", command=self.tree.yview)
        hbar = ttk.Scrollbar(panel, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        vbar.grid(row=2, column=1, sticky="ns", padx=(0, 14))
        hbar.grid(row=3, column=0, sticky="ew", padx=14)
        footer = ctk.CTkFrame(panel, fg_color="transparent")
        footer.grid(row=4, column=0, columnspan=2, sticky="ew", padx=14, pady=8)
        footer.grid_columnconfigure(0, weight=1)
        self.result_count = ctk.StringVar(value="0 résultat")
        self.page_info = ctk.StringVar(value="1 / 1")
        ctk.CTkLabel(footer, textvariable=self.result_count, text_color=COLORS["muted"]).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(footer, text="<", width=36, command=lambda: self._change_page(-1)).grid(row=0, column=1, padx=4)
        ctk.CTkLabel(footer, textvariable=self.page_info, width=80, text_color=COLORS["text"]).grid(row=0, column=2)
        ctk.CTkButton(footer, text=">", width=36, command=lambda: self._change_page(1)).grid(row=0, column=3, padx=4)
        ctk.CTkButton(footer, text="Voir les vulnérabilités", command=self._show_selected_detail).grid(row=0, column=4, padx=(10, 0))

    def _right_panel(self, parent: ctk.CTkFrame) -> None:
        right = ctk.CTkScrollableFrame(parent, fg_color="transparent", width=380)
        right.grid(row=0, column=1, sticky="nsew")
        self.risk_canvas = ctk.CTkCanvas(right, width=350, height=155, bg=COLORS["panel"], highlightthickness=1, highlightbackground=COLORS["border"])
        self.risk_canvas.pack(fill="x", pady=(0, 10))
        actions = ctk.CTkFrame(right, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        actions.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(actions, text="Actions rapides", font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 8))
        ctk.CTkButton(actions, text="Exporter PDF", anchor="w", fg_color="transparent", hover_color=COLORS["panel2"], command=self.export_current_pdf).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(actions, text="Exporter Excel", anchor="w", fg_color="transparent", hover_color=COLORS["panel2"], command=self.export_current_excel).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(actions, text="Exporter CSV", anchor="w", fg_color="transparent", hover_color=COLORS["panel2"], command=self.export_current_csv).pack(fill="x", padx=10, pady=(2, 12))
        info = ctk.CTkFrame(right, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        info.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(info, text="Informations du scan", font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 8))
        self.scan_info = ctk.StringVar(value="État          En attente\nCible         -\nDurée         -\nProgression   0%\nVitesse       -\nHôte courant  -")
        ctk.CTkLabel(info, textvariable=self.scan_info, justify="left", anchor="w", text_color=COLORS["muted"], font=("Consolas", 10)).pack(fill="x", padx=14, pady=(0, 10))
        log = ctk.CTkFrame(right, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        log.pack(fill="both", expand=True)
        ctk.CTkLabel(log, text="Journal d'activité", font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 6))
        self.activity_text = ctk.CTkTextbox(log, height=120, fg_color="#0A1727", text_color=COLORS["muted"], font=("Consolas", 10))
        self.activity_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._draw_risk_chart()

    def _progress_panel(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(parent, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        panel.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        panel.grid_columnconfigure(1, weight=1)
        self.status_text = ctk.StringVar(value="Prêt à scanner")
        ctk.CTkLabel(panel, textvariable=self.status_text, text_color=COLORS["text"], font=("Segoe UI", 16, "bold"), anchor="w").grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(14, 6))
        self.progress = ctk.CTkProgressBar(panel, progress_color=COLORS["cyan"])
        self.progress.set(0)
        self.progress.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        self.progress_label = ctk.StringVar(value="0%")
        ctk.CTkLabel(panel, textvariable=self.progress_label, text_color=COLORS["text"], width=60).grid(row=1, column=2, padx=12)

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan en cours", "Un scan est déjà en cours.")
            return
        try:
            target = self._resolve_target()
            if not self._confirm_authorization(target):
                return
            if self.profile.get() == "Scan complet" and not messagebox.askyesno("Scan complet", "Le scan complet teste 1 à 65535 ports et peut être très long. Continuer ?"):
                return
            if self.target_mode.get() == "Liste d'adresses IP":
                parse_ip_list(target)
            else:
                parse_target(target)
            ports = ports_for_profile(self.profile.get(), self.custom_ports.get())
        except ValueError as exc:
            messagebox.showerror("Cible invalide", str(exc))
            return
        if not ports:
            self.start_discovery(ping_only=True)
            return
        self.scan_started_at = time.perf_counter()
        self.findings.clear()
        self.activity.clear()
        self.current_summary = None
        self.progress_state = {"done": 0, "total": 0, "host": "-"}
        self._apply_filters()
        self._set_stats()
        self.progress.set(0)
        self.progress_label.set("0%")
        self.status_text.set("Scan en cours...")
        self._log_activity(f"Démarrage du scan {target}")
        self.scan_thread = threading.Thread(target=self._run_scan, args=(target, ports), daemon=True)
        self.scan_thread.start()

    def start_discovery(self, ping_only: bool | None = None) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan en cours", "Une opération est déjà en cours.")
            return
        try:
            target = self._resolve_target()
            if not self._confirm_authorization(target):
                return
            if self.target_mode.get() == "Liste d'adresses IP":
                parse_ip_list(target)
            else:
                parse_target(target)
        except ValueError as exc:
            messagebox.showerror("Cible invalide", str(exc))
            return
        self.devices.clear()
        self.view_mode.set("Appareils")
        self._render_current_view()
        self.progress.set(0)
        self.progress_label.set("0%")
        self.status_text.set("Découverte en cours...")
        self.scan_started_at = time.perf_counter()
        self._log_activity(f"Découverte des appareils {target}")
        effective_ping_only = self.profile.get() == "Ping uniquement" if ping_only is None else ping_only
        self.scan_thread = threading.Thread(target=self._run_discovery, args=(target, effective_ping_only), daemon=True)
        self.scan_thread.start()

    def _run_discovery(self, target: str, ping_only: bool) -> None:
        try:
            devices = self.discoverer.discover(
                target,
                ping_only=ping_only,
                include_unreachable=self.show_unreachable.get() == 1,
                on_device=lambda device: self.events.put(("device", device)),
                on_progress=lambda done, total, host: self.events.put(("discovery_progress", (done, total, host))),
            )
            self.events.put(("discovery_complete", devices))
        except (OSError, RuntimeError, ValueError) as exc:
            self.events.put(("error", str(exc)))

    def _run_scan(self, target: str, ports: list[int]) -> None:
        def progress(done: int, total: int, host: str) -> None:
            self.events.put(("progress", (done, total, host)))

        def finding(item: ScanFinding) -> None:
            self.events.put(("finding", item))

        def event(kind: str, payload: dict[str, object]) -> None:
            self.events.put(("scan_event", (kind, payload)))

        try:
            summary = self.scanner.scan(target, ports, progress, finding, event)
            self.repository.save_scan(summary)
            self.events.put(("complete", summary))
        except (OSError, RuntimeError, ValueError) as exc:
            self.events.put(("error", str(exc)))

    def stop_scan(self) -> None:
        self.scanner.stop()
        self.discoverer.stop()
        self.status_text.set("Arrêt demandé...")
        self._log_activity("Arrêt demandé")

    def _process_events(self) -> None:
        while not self.events.empty():
            kind, payload = self.events.get()
            if kind == "finding":
                self.findings.append(payload)  # type: ignore[arg-type]
                self._apply_filters()
                self._set_stats()
            elif kind == "progress":
                done, total, host = payload  # type: ignore[misc]
                self.progress_state = {"done": done, "total": total, "host": host}
                self._update_progress_info()
            elif kind == "device":
                self._upsert_device(payload)  # type: ignore[arg-type]
                self._set_stats()
                self._render_current_view()
            elif kind == "discovery_progress":
                done, total, host = payload  # type: ignore[misc]
                self.progress_state = {"done": done, "total": total, "host": host}
                self._update_progress_info()
            elif kind == "discovery_complete":
                self.devices = list(payload)  # type: ignore[arg-type]
                self.status_text.set("Découverte terminée")
                self.progress.set(1)
                self.progress_label.set("100%")
                self._set_stats()
                self._render_current_view()
                self._log_activity("Découverte terminée")
            elif kind == "ping_sample":
                self._update_ping_window(payload)  # type: ignore[arg-type]
            elif kind == "scan_event":
                event_kind, data = payload  # type: ignore[misc]
                self._handle_scan_event(event_kind, data)
            elif kind == "complete":
                self.current_summary = payload  # type: ignore[assignment]
                self.status_text.set("Scan terminé")
                self.progress.set(1)
                self.progress_label.set("100%")
                self._set_stats()
                self._refresh_history()
                self._log_activity("Scan terminé")
                self._update_progress_info(final=True)
            elif kind == "error":
                self.status_text.set("Erreur")
                self._log_activity(f"Erreur récupérable : {payload}")
                messagebox.showerror("Erreur de scan", str(payload))
        self.after(self.settings.ui_refresh_ms, self._process_events)

    def _update_ping_window(self, payload: tuple[ctk.CTkToplevel, ctk.StringVar, ctk.CTkTextbox, dict[str, int], list[float], float | None]) -> None:
        win, stats, log, counters, latencies, latency = payload
        if not win.winfo_exists():
            return
        sent = counters["sent"]
        received = counters["received"]
        lost = sent - received
        loss_pct = (lost / sent * 100) if sent else 0
        if latencies:
            min_latency = min(latencies)
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            latency_line = f"{min_latency:.1f} / {avg_latency:.1f} / {max_latency:.1f} ms"
        else:
            latency_line = "- / - / - ms"
        stats.set(f"Paquets envoyés : {sent}\nPaquets reçus : {received}\nPerdus : {lost} ({loss_pct:.0f}%)\nMin/Moy/Max : {latency_line}")
        log.configure(state="normal")
        log.insert("end", f"{time.strftime('%H:%M:%S')}  {'timeout' if latency is None else f'{latency:.1f} ms'}\n")
        log.see("end")
        log.configure(state="disabled")

    def _handle_scan_event(self, kind: str, data: dict[str, object]) -> None:
        if kind == "port_open":
            self._log_activity(f"Port ouvert {data.get('host')}:{data.get('port')} ({data.get('service')})")
        elif kind == "service_detected":
            product = data.get("product") or "service sans version"
            version = data.get("version") or ""
            self._log_activity(f"Service identifié {data.get('host')}:{data.get('port')} {product} {version}".strip())
        elif kind == "cve_lookup":
            self._log_activity(f"Recherche CVE {data.get('product')} {data.get('version') or ''}".strip())
        elif kind == "scan_stopped":
            self._log_activity("Scan arrêté")
        elif kind == "scan_completed":
            self._log_activity("Scan terminé")

    def _apply_filters(self) -> None:
        query = self.search_entry.get().lower() if hasattr(self, "search_entry") else ""
        risk = self.risk_filter.get() if hasattr(self, "risk_filter") else "Tous"
        cve_filter = self.cve_filter.get() if hasattr(self, "cve_filter") else "Toutes CVE"
        self.filtered = [
            item
            for item in self.findings
            if (risk == "Tous" or item.risk == risk)
            and self._matches_cve_filter(item, cve_filter)
            and query in " ".join(map(str, item.to_dict().values())).lower()
        ]
        self.page = min(self.page, max(1, (len(self.filtered) + self.page_size - 1) // self.page_size))
        self._render_current_view()
        self._draw_risk_chart()

    def _render_current_view(self) -> None:
        if hasattr(self, "view_mode") and self.view_mode.get() == "Appareils":
            self._render_devices_table()
        else:
            self._render_table()

    def _matches_cve_filter(self, item: ScanFinding, value: str) -> bool:
        if value == "Toutes CVE":
            return True
        if value == "CISA KEV":
            return any(cve.kev for cve in item.cves)
        if value == "Confirmé/Probable":
            return item.fingerprint.confidence in {"Confirmé", "Probable"}
        severity_map = {"Critique": "CRITICAL", "Élevé": "HIGH", "Moyen": "MEDIUM", "Faible": "LOW"}
        return any(cve.severity.upper() == severity_map.get(value, "") for cve in item.cves)

    def _render_table(self) -> None:
        self._configure_columns(
            ("ip", "hostname", "port", "service", "product", "version", "cves", "cvss", "kev", "confidence", "risk", "description", "recommendation"),
            ["Adresse IP", "Nom d'hôte", "Port", "Service", "Produit", "Version", "CVE", "CVSS max", "KEV", "Confiance", "Risque", "Description", "Recommandation"],
            [115, 130, 60, 95, 145, 95, 80, 80, 70, 150, 90, 300, 340],
        )
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)
        start = (self.page - 1) * self.page_size
        for item in self.filtered[start : start + self.page_size]:
            max_cvss = max((cve.cvss_score for cve in item.cves), default=0)
            tags = []
            if any(cve.severity.upper() == "CRITICAL" for cve in item.cves):
                tags.append("critical_cve")
            if any(cve.kev for cve in item.cves):
                tags.append("kev")
            self.tree.insert(
                "",
                "end",
                values=(
                    item.ip,
                    item.hostname,
                    item.port,
                    item.service,
                    item.fingerprint.product,
                    item.fingerprint.version,
                    len(item.cves),
                    max_cvss or "",
                    "Oui" if any(cve.kev for cve in item.cves) else "Non",
                    item.fingerprint.confidence,
                    item.risk,
                    item.description,
                    item.recommendation,
                ),
                tags=tuple(tags),
            )
        total_pages = max(1, (len(self.filtered) + self.page_size - 1) // self.page_size)
        self.result_count.set(f"{len(self.filtered)} résultat(s)")
        self.page_info.set(f"{self.page} / {total_pages}")

    def _render_devices_table(self) -> None:
        self._configure_columns(
            ("status", "ip", "hostname", "mac", "vendor", "latency", "method", "ports", "risk", "last_seen"),
            ["Statut", "IP", "Nom", "MAC", "Fabricant", "Latence", "Méthode", "Ports ouverts", "Risque", "Dernière détection"],
            [105, 115, 150, 145, 150, 90, 100, 110, 90, 160],
        )
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)
        query = self.search_entry.get().lower() if hasattr(self, "search_entry") else ""
        self.displayed_devices = [device for device in self.devices if query in " ".join(map(str, device.__dict__.values())).lower()]
        for device in self.displayed_devices:
            self.tree.insert(
                "",
                "end",
                values=(
                    device.status,
                    device.ip,
                    device.hostname,
                    device.mac,
                    device.vendor,
                    "-" if device.latency_ms is None else f"{device.latency_ms:.1f} ms",
                    device.discovery_method,
                    len(device.open_ports),
                    device.risk,
                    device.last_seen,
                ),
            )
        self.result_count.set(f"{len(self.displayed_devices)} appareil(s)")
        self.page_info.set("1 / 1")

    def _configure_columns(self, columns: tuple[str, ...], labels: list[str], widths: list[int]) -> None:
        if getattr(self, "_current_columns", None) == columns:
            return
        self.tree.configure(columns=columns)
        for col, label, width in zip(columns, labels, widths):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=min(width, 80), stretch=col in {"description", "recommendation", "product", "vendor"})
        self._current_columns = columns

    def _change_page(self, delta: int) -> None:
        total_pages = max(1, (len(self.filtered) + self.page_size - 1) // self.page_size)
        self.page = min(max(1, self.page + delta), total_pages)
        self._render_current_view()

    def _set_stats(self) -> None:
        hosts = len({item.ip for item in self.findings} | {device.ip for device in self.devices if device.status == "Joignable"})
        ports = len(self.findings)
        critical = sum(1 for item in self.findings if item.risk == "CRITIQUE")
        exposures = sum(1 for item in self.findings if item.risk in {"CRITIQUE", "ÉLEVÉ"})
        cves = sum(len(item.cves) for item in self.findings)
        critical_cves = sum(1 for item in self.findings for cve in item.cves if cve.severity.upper() == "CRITICAL")
        kev = sum(1 for item in self.findings for cve in item.cves if cve.kev)
        no_version = sum(1 for item in self.findings if not item.fingerprint.version)
        values = {
            "hosts": hosts,
            "ports": ports,
            "critical": critical,
            "exposures": exposures,
            "cves": cves,
            "critical_cves": critical_cves,
            "kev": kev,
            "no_version": no_version,
        }
        for key, value in values.items():
            self.stat_vars[key].set(str(value))
        self._draw_risk_chart()

    def _update_progress_info(self, final: bool = False) -> None:
        done = int(self.progress_state.get("done", 0))
        total = int(self.progress_state.get("total", 0))
        host = str(self.progress_state.get("host", "-"))
        elapsed = time.perf_counter() - self.scan_started_at if self.scan_started_at else 0
        ratio = done / total if total else (1 if final else 0)
        speed = done / elapsed if elapsed > 0 else 0
        self.progress.set(ratio)
        self.progress_label.set(f"{ratio:.0%}")
        self.scan_info.set(
            f"État          {'Terminé' if final else 'Scan en cours'}\n"
            f"Cible         {self.target_entry.get()}\n"
            f"Durée         {elapsed:.1f}s\n"
            f"Progression   {ratio:.0%}\n"
            f"Vitesse       {speed:.1f} ports/s\n"
            f"Hôte courant  {host}"
        )

    def _draw_risk_chart(self) -> None:
        self.risk_canvas.delete("all")
        self.risk_canvas.create_text(14, 16, text="Répartition des risques", anchor="w", fill=COLORS["text"], font=("Segoe UI", 12, "bold"))
        counts = Counter(item.risk for item in self.findings)
        total = sum(counts.values()) or 1
        start = 90
        for risk in ["CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE"]:
            extent = counts[risk] / total * 360
            self.risk_canvas.create_arc(38, 42, 158, 162, start=start, extent=extent, fill=RISK_COLORS[risk], outline=COLORS["panel"])
            start += extent
        self.risk_canvas.create_oval(68, 72, 128, 132, fill=COLORS["panel"], outline=COLORS["panel"])
        self.risk_canvas.create_text(98, 94, text=str(sum(counts.values())), fill=COLORS["text"], font=("Segoe UI", 20, "bold"))
        self.risk_canvas.create_text(98, 116, text="Ports ouverts", fill=COLORS["text"], font=("Segoe UI", 8))
        y = 56
        for risk in ["CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE"]:
            pct = counts[risk] / total * 100 if sum(counts.values()) else 0
            self.risk_canvas.create_oval(190, y - 5, 202, y + 7, fill=RISK_COLORS[risk], outline="")
            self.risk_canvas.create_text(214, y + 1, text=f"{risk.title()}  {counts[risk]} ({pct:.0f}%)", anchor="w", fill=COLORS["text"], font=("Segoe UI", 10))
            y += 28

    def _show_selected_detail(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Détail", "Sélectionnez une ligne.")
            return
        index = self.tree.index(selected[0]) + (self.page - 1) * self.page_size
        if index >= len(self.filtered) and self.view_mode.get() != "Appareils":
            return
        if self.view_mode.get() == "Appareils":
            devices = self.displayed_devices
            if index >= len(devices):
                return
            self._show_device_detail(devices[index])
            return
        finding = self.filtered[index]
        win = ctk.CTkToplevel(self)
        win.title(f"Vulnérabilités - {finding.ip}:{finding.port}")
        win.geometry("880x620")
        text = ctk.CTkTextbox(win, wrap="word", fg_color=COLORS["panel"], text_color=COLORS["text"])
        text.pack(fill="both", expand=True, padx=16, pady=16)
        text.insert("end", f"Service : {finding.service}\nProduit : {finding.fingerprint.product or '-'}\nVersion : {finding.fingerprint.version or '-'}\nCPE : {finding.fingerprint.cpe or '-'}\nConfiance : {finding.fingerprint.confidence}\n\n")
        text.insert("end", f"Bannière :\n{finding.fingerprint.banner or '-'}\n\n")
        if not finding.cves:
            text.insert("end", "Aucune CVE associée. Sans produit/version fiable, NetScope évite les faux positifs.\n")
        for cve in finding.cves:
            text.insert("end", f"{cve.cve_id} | {cve.severity} | CVSS {cve.cvss_score} | KEV {'Oui' if cve.kev else 'Non'}\n")
            text.insert("end", f"Confiance : {cve.confidence}\nCWE : {cve.cwe or '-'}\nPublication : {cve.published}\nModification : {cve.last_modified}\n")
            text.insert("end", f"Description : {cve.description}\nRecommandation : {cve.recommendation}\n")
            text.insert("end", "Liens officiels :\n" + "\n".join(cve.references[:8]) + "\n\n")
        text.configure(state="disabled")

    def _show_device_detail(self, device: DiscoveredDevice) -> None:
        win = ctk.CTkToplevel(self)
        win.title(f"Appareil - {device.ip}")
        win.geometry("620x460")
        text = ctk.CTkTextbox(win, wrap="word", fg_color=COLORS["panel"], text_color=COLORS["text"])
        text.pack(fill="both", expand=True, padx=16, pady=16)
        text.insert("end", f"Statut : {device.status}\nIP : {device.ip}\nNom : {device.hostname}\nMAC : {device.mac}\nFabricant : {device.vendor}\nLatence : {device.latency_ms or '-'} ms\nMéthode : {device.discovery_method}\nPorts ouverts : {', '.join(map(str, device.open_ports)) or '-'}\nServices : {', '.join(device.services) or '-'}\nRisque : {device.risk}\nDernière détection : {device.last_seen}\n\n")
        text.insert("end", "Pour scanner uniquement cet équipement, copiez son IP dans le champ cible ou double-cliquez puis utilisez le bouton ci-dessous.\n")
        text.configure(state="disabled")
        actions = ctk.CTkFrame(win, fg_color="transparent")
        actions.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkButton(actions, text="Scanner cet équipement", command=lambda: self._scan_device_from_detail(win, device.ip)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Ping continu", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=lambda: self._open_ping_window(device.ip)).pack(side="left")

    def _scan_device_from_detail(self, win: ctk.CTkToplevel, ip: str) -> None:
        win.destroy()
        self.target_mode.set("Une adresse IP")
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, ip)
        self.start_scan()

    def _log_activity(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.activity.append(f"[{stamp}] {message}")
        if hasattr(self, "activity_text"):
            self.activity_text.configure(state="normal")
            self.activity_text.delete("1.0", "end")
            self.activity_text.insert("end", "\n".join(self.activity))
            self.activity_text.see("end")
            self.activity_text.configure(state="disabled")

    def export_current_pdf(self) -> None:
        if not self.current_summary:
            messagebox.showinfo("Export", "Aucun scan terminé à exporter.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], initialfile="rapport-netscope.pdf")
        if path:
            export_pdf(self.current_summary, Path(path))
            messagebox.showinfo("Export PDF", "Rapport PDF généré.")

    def export_current_excel(self) -> None:
        if not self.current_summary:
            messagebox.showinfo("Export", "Aucun scan terminé à exporter.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")], initialfile="rapport-netscope.xlsx")
        if path:
            export_excel(self.current_summary, Path(path))
            messagebox.showinfo("Export Excel", "Fichier Excel généré.")

    def export_current_csv(self) -> None:
        if not self.current_summary:
            messagebox.showinfo("Export", "Aucun scan terminé à exporter.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="rapport-netscope.csv")
        if path:
            export_csv(self.current_summary, Path(path))
            messagebox.showinfo("Export CSV", "Fichier CSV généré.")

    def _refresh_history(self) -> None:
        self.history_rows = self.repository.list_scans()

    def _load_interfaces(self) -> None:
        self.interfaces = active_interfaces()
        values = [f"{item.name} - {item.ipv4} ({item.cidr})" for item in self.interfaces] or ["Aucune interface active"]
        if hasattr(self, "interface_menu"):
            self.interface_menu.configure(values=values)
            self.interface_menu.set(values[0])
        default = choose_default_interface(self.interfaces)
        if default and hasattr(self, "target_entry") and self.target_entry.get().startswith("192.168.1."):
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, default.cidr)

    def detect_my_network(self) -> None:
        interface = self._selected_interface() or choose_default_interface(self.interfaces)
        if not interface:
            messagebox.showerror("Réseau", "Aucune interface IPv4 active détectée.")
            return
        self.target_mode.set("Tout mon réseau local")
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, interface.cidr)
        messagebox.showinfo("Réseau détecté", f"Interface : {interface.name}\nIPv4 : {interface.ipv4}\nMasque : {interface.netmask}\nPasserelle : {interface.gateway}\nMAC : {interface.mac}\nCIDR : {interface.cidr}\n\nLa cible a été remplie. Le scan ne démarre qu'après confirmation via le bouton.")

    def _selected_interface(self) -> NetworkInterfaceInfo | None:
        selected = self.interface_menu.get() if hasattr(self, "interface_menu") else ""
        for item in self.interfaces:
            if selected.startswith(f"{item.name} - "):
                return item
        return None

    def _mode_changed(self) -> None:
        mode = self.target_mode.get()
        interface = self._selected_interface() or choose_default_interface(self.interfaces)
        if mode == "Ma machine" and interface:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, interface.ipv4)
        elif mode == "Tout mon réseau local" and interface:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, interface.cidr)

    def _resolve_target(self) -> str:
        mode = self.target_mode.get()
        interface = self._selected_interface() or choose_default_interface(self.interfaces)
        if mode == "Ma machine" and interface:
            return interface.ipv4
        if mode == "Tout mon réseau local" and interface:
            return self.target_entry.get().strip() or interface.cidr
        return self.target_entry.get().strip()

    def _upsert_device(self, device: DiscoveredDevice) -> None:
        self.devices = [item for item in self.devices if item.ip != device.ip]
        self.devices.append(device)
        self.devices.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")))

    def _confirm_authorization(self, target: str) -> bool:
        if self.authorization_check.get() != 1:
            messagebox.showwarning("Autorisation requise", "Confirmez que vous êtes autorisé à analyser cette cible avant de lancer une découverte ou un scan.")
            return False
        try:
            safety = enforce_target_policy(target, max_hosts=self.max_hosts_default)
        except ValueError as exc:
            messagebox.showerror("Cible refusée", str(exc))
            return False
        if safety.contains_public:
            return messagebox.askyesno("Adresse publique détectée", f"{safety.message}\n\nContinuer uniquement si vous avez une autorisation écrite.")
        return True

    def _open_ping_window(self, ip: str) -> None:
        from scanner.discovery import ping

        win = ctk.CTkToplevel(self)
        win.title(f"Ping continu - {ip}")
        win.geometry("520x360")
        stats = ctk.StringVar(value="Paquets envoyés : 0\nPaquets reçus : 0\nPerdus : 0 (0%)\nMin/Moy/Max : - / - / - ms")
        running = threading.Event()
        running.set()
        latencies: list[float] = []
        counters = {"sent": 0, "received": 0}

        ctk.CTkLabel(win, text=f"Ping continu vers {ip}", font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))
        ctk.CTkLabel(win, textvariable=stats, justify="left", font=("Consolas", 13), text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=8)
        log = ctk.CTkTextbox(win, height=150, fg_color=COLORS["panel"], text_color=COLORS["muted"], font=("Consolas", 10))
        log.pack(fill="both", expand=True, padx=16, pady=8)

        def worker() -> None:
            while running.is_set():
                counters["sent"] += 1
                latency = ping(ip, 1.0)
                if latency is not None:
                    counters["received"] += 1
                    latencies.append(latency)
                self.events.put(("ping_sample", (win, stats, log, dict(counters), list(latencies), latency)))
                time.sleep(1)

        def stop() -> None:
            running.clear()
            win.destroy()

        ctk.CTkButton(win, text="Arrêter le ping", fg_color=COLORS["red"], command=stop).pack(pady=(0, 12))
        win.protocol("WM_DELETE_WINDOW", stop)
        threading.Thread(target=worker, daemon=True).start()

    def _show_history(self) -> None:
        rows = getattr(self, "history_rows", [])
        if not rows:
            messagebox.showinfo("Historique", "Aucun scan enregistré.")
            return
        win = ctk.CTkToplevel(self)
        win.title("Historique des scans")
        win.geometry("920x560")
        win.configure(fg_color=COLORS["bg"])
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(win, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Historique des scans", font=("Segoe UI", 22, "bold"), text_color=COLORS["text"]).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Consultez, exportez ou supprimez les analyses enregistrées.", text_color=COLORS["muted"]).grid(row=1, column=0, sticky="w", pady=(2, 0))

        table_frame = ctk.CTkFrame(win, fg_color=COLORS["panel"], border_width=1, border_color=COLORS["border"])
        table_frame.grid(row=1, column=0, sticky="nsew", padx=18, pady=8)
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("id", "date", "target", "duration", "hosts", "ports", "critical", "exposures")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        labels = ["ID", "Date", "Cible", "Durée", "Hôtes", "Ports", "Critiques", "Élevées"]
        widths = [60, 165, 190, 80, 80, 80, 90, 90]
        for col, label, width in zip(columns, labels, widths):
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=50, stretch=col in {"target", "date"})
        for row in rows:
            tree.insert(
                "",
                "end",
                values=(
                    row["id"],
                    row["created_at"],
                    row["target"],
                    f"{float(row['duration_seconds']):.1f}s",
                    row["host_count"],
                    row["open_port_count"],
                    row["critical_count"],
                    row["threat_count"],
                ),
            )
        tree.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 12), pady=12)

        actions = ctk.CTkFrame(win, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=18, pady=(8, 18))
        actions.grid_columnconfigure(0, weight=1)

        def selected_scan_id() -> int | None:
            selection = tree.selection()
            if not selection:
                messagebox.showinfo("Historique", "Sélectionnez un scan.")
                return None
            return int(tree.item(selection[0], "values")[0])

        def load_selected() -> None:
            scan_id = selected_scan_id()
            if scan_id is None:
                return
            summary = self.repository.get_scan(scan_id)
            self.current_summary = summary
            self.findings = list(summary.findings)
            self.devices.clear()
            self.view_mode.set("Ports et vulnérabilités")
            self._apply_filters()
            self._set_stats()
            self.status_text.set(f"Scan #{scan_id} chargé")
            self.scan_info.set(
                f"État          Historique\n"
                f"Cible         {summary.target}\n"
                f"Durée         {summary.duration_seconds:.1f}s\n"
                f"Progression   100%\n"
                f"Vitesse       -\n"
                f"Hôte courant  -"
            )
            win.destroy()

        def delete_selected() -> None:
            scan_id = selected_scan_id()
            if scan_id is None:
                return
            if not messagebox.askyesno("Suppression", f"Supprimer définitivement le scan #{scan_id} ?"):
                return
            self.repository.delete_scan(scan_id)
            for item in tree.selection():
                tree.delete(item)
            self._refresh_history()

        def export_selected(kind: str) -> None:
            scan_id = selected_scan_id()
            if scan_id is None:
                return
            summary = self.repository.get_scan(scan_id)
            if kind == "pdf":
                path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], initialfile=f"rapport-netscope-{scan_id}.pdf")
                if path:
                    export_pdf(summary, Path(path))
            elif kind == "xlsx":
                path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")], initialfile=f"rapport-netscope-{scan_id}.xlsx")
                if path:
                    export_excel(summary, Path(path))
            else:
                path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile=f"rapport-netscope-{scan_id}.csv")
                if path:
                    export_csv(summary, Path(path))

        ctk.CTkButton(actions, text="Charger", command=load_selected).grid(row=0, column=1, padx=4)
        ctk.CTkButton(actions, text="Exporter PDF", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=lambda: export_selected("pdf")).grid(row=0, column=2, padx=4)
        ctk.CTkButton(actions, text="Exporter Excel", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=lambda: export_selected("xlsx")).grid(row=0, column=3, padx=4)
        ctk.CTkButton(actions, text="Exporter CSV", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=lambda: export_selected("csv")).grid(row=0, column=4, padx=4)
        ctk.CTkButton(actions, text="Supprimer", fg_color=COLORS["red"], command=delete_selected).grid(row=0, column=5, padx=4)
        ctk.CTkButton(actions, text="Fermer", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=win.destroy).grid(row=0, column=6, padx=(12, 0))

    def _switch_view(self, value: str) -> None:
        if hasattr(self, "view_mode"):
            self.view_mode.set(value)
            self._render_current_view()

    def _show_reports_info(self) -> None:
        actions = [
            ("Ouvrir l'historique", self._show_history),
            ("Fermer", None),
        ]
        self._show_info_window(
            "Rapports",
            "Rapports et exports",
            "Les exports PDF, Excel et CSV sont disponibles après un scan terminé. Vous pouvez aussi ouvrir l'historique pour exporter une ancienne analyse.",
            actions,
        )

    def _show_ping_help(self) -> None:
        actions = [
            ("Vue Appareils", lambda: self._switch_view("Appareils")),
            ("Fermer", None),
        ]
        self._show_info_window(
            "Ping et diagnostic",
            "Ping et diagnostic",
            "Ouvrez la vue Appareils, double-cliquez sur un équipement, puis utilisez Ping continu. Le diagnostic affiche paquets envoyés, reçus, perte et latences.",
            actions,
        )

    def _show_about(self) -> None:
        self._show_info_window(
            "À propos",
            f"NetScope Scanner {APP_VERSION}",
            "Scanner réseau défensif pour environnements autorisés.\n\nAucun exploit, brute force ou contournement d'authentification.\nLes CVE ne sont jamais inventées et restent potentielles sans produit/version fiable.",
            [("Fermer", None)],
        )

    def _show_info_window(self, title: str, heading: str, body: str, actions: list[tuple[str, object | None]]) -> None:
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("620x330")
        win.minsize(520, 280)
        win.configure(fg_color=COLORS["bg"])
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(win, text=heading, font=("Segoe UI", 22, "bold"), text_color=COLORS["text"], anchor="w").grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 8))
        text = ctk.CTkTextbox(win, wrap="word", fg_color=COLORS["panel"], text_color=COLORS["text"], border_width=1, border_color=COLORS["border"], font=("Segoe UI", 13))
        text.grid(row=1, column=0, sticky="nsew", padx=22, pady=8)
        text.insert("end", body)
        text.configure(state="disabled")

        footer = ctk.CTkFrame(win, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 20))
        footer.grid_columnconfigure(0, weight=1)
        for index, (label, command) in enumerate(actions, start=1):
            if command is None:
                button_command = win.destroy
            else:
                def button_command(command=command) -> None:
                    win.destroy()
                    command()
            ctk.CTkButton(
                footer,
                text=label,
                fg_color=COLORS["cyan"] if index == 1 else COLORS["panel2"],
                border_width=0 if index == 1 else 1,
                border_color=COLORS["border"],
                command=button_command,
            ).grid(row=0, column=index, padx=(8, 0))

    def _show_settings(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Paramètres")
        win.geometry("620x620")
        fields: dict[str, ctk.CTkEntry] = {}
        values = {
            "max_workers": str(self.settings.max_workers),
            "discovery_timeout": str(self.settings.discovery_timeout),
            "tcp_timeout": str(self.settings.tcp_timeout),
            "banner_timeout": str(self.settings.banner_timeout),
            "retries": str(self.settings.retries),
            "ui_refresh_ms": str(self.settings.ui_refresh_ms),
            "max_hosts": str(self.settings.max_hosts),
            "cve_cache_days": str(self.settings.cve_cache_days),
            "report_dir": self.settings.report_dir,
            "history_retention_days": str(self.settings.history_retention_days),
        }
        offline_var = ctk.BooleanVar(value=self.settings.offline_mode)
        nmap_var = ctk.BooleanVar(value=self.settings.nmap_enabled)
        ctk.CTkLabel(win, text="Paramètres", font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=18, pady=(18, 8))
        form = ctk.CTkScrollableFrame(win, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=18, pady=8)
        for key, value in values.items():
            ctk.CTkLabel(form, text=key, anchor="w").pack(fill="x", pady=(8, 2))
            entry = ctk.CTkEntry(form)
            entry.insert(0, value)
            entry.pack(fill="x")
            fields[key] = entry
        ctk.CTkCheckBox(form, text="Mode hors ligne CVE", variable=offline_var).pack(anchor="w", pady=(12, 4))
        ctk.CTkCheckBox(form, text="Activer Nmap optionnel si disponible", variable=nmap_var).pack(anchor="w", pady=4)

        def save() -> None:
            try:
                new_settings = AppSettings(
                    max_workers=int(fields["max_workers"].get()),
                    discovery_timeout=float(fields["discovery_timeout"].get()),
                    tcp_timeout=float(fields["tcp_timeout"].get()),
                    banner_timeout=float(fields["banner_timeout"].get()),
                    retries=int(fields["retries"].get()),
                    ui_refresh_ms=int(fields["ui_refresh_ms"].get()),
                    max_hosts=int(fields["max_hosts"].get()),
                    cve_cache_days=int(fields["cve_cache_days"].get()),
                    report_dir=fields["report_dir"].get(),
                    history_retention_days=int(fields["history_retention_days"].get()),
                    offline_mode=offline_var.get(),
                    nmap_enabled=nmap_var.get(),
                )
                validate_settings(new_settings)
            except ValueError as exc:
                messagebox.showerror("Paramètres invalides", str(exc))
                return
            save_settings(new_settings)
            self.settings = new_settings
            self.max_hosts_default = new_settings.max_hosts
            self.scanner = self._build_scanner()
            self.discoverer = self._build_discoverer()
            messagebox.showinfo("Paramètres", "Paramètres enregistrés et appliqués.")
            win.destroy()

        def restore() -> None:
            save_settings(recommended_settings())
            messagebox.showinfo("Paramètres", "Paramètres recommandés restaurés. Redémarrez l'application pour tout recharger.")
            win.destroy()

        buttons = ctk.CTkFrame(win, fg_color="transparent")
        buttons.pack(fill="x", padx=18, pady=(0, 16))
        ctk.CTkButton(buttons, text="Enregistrer", command=save).pack(side="left", padx=(0, 8))
        ctk.CTkButton(buttons, text="Restaurer recommandés", fg_color=COLORS["panel2"], border_width=1, border_color=COLORS["border"], command=restore).pack(side="left")
