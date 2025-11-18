from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PortAssessment:
    """
    Descrive la valutazione di rischio associata a una porta/servizio

    Attributes:
        port (int): Numero di porta TCP/UDP (o -1 se derivato solo dal nome servizio).
        service (str): Nome del servizio (es. "ssh", "http", "rdp").
        level (str): Livello di rischio: 'expected', 'caution', 'danger' o 'unknown'.
        color (str): Colore esadecimale associato al livello (per uso HTML).
        reason (str): Motivazione sintetica della classificazione.
    """

    port: int
    service: str
    level: str      # 'expected' | 'caution' | 'danger' | 'unknown'
    color: str      # hex per HTML, es. '#22c55e'
    reason: str


#Mappatura livello -> colore HTML
COLORS = {
    "expected": "#22c55e",  # verde
    "caution": "#eab308",   # giallo
    "danger": "#ef4444",    # rosso
    "unknown": "#94a3b8",   # grigio
}

#Porte considerate ad alta esposizione o rischio se accessibili dall'esterno
DANGEROUS_PORTS = {
    23: "Telnet esposto",
    445: "SMB/445 esposto",
    139: "NetBIOS/139 esposto",
    3389: "RDP esposto",
    5900: "VNC esposto",
    3306: "MySQL esposto",
    5432: "PostgreSQL esposto",
    27017: "MongoDB esposto",
    6379: "Redis esposto",
    9200: "Elasticsearch esposto",
    2375: "Docker API",
    2376: "Docker API (verificare TLS)",
    10250: "Kubelet API esposta",
    21: "FTP esposto",
    69: "TFTP esposto",
    2049: "NFS esposto",
}

#Porte comunemente attese su un server esposto (non necessariamente "sicure")
EXPECTED_PORTS = {
    22: "SSH",
    80: "HTTP pubblico",
    443: "HTTPS pubblico",
    8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
    53: "DNS",
    25: "SMTP",
    587: "SMTP submission",
    465: "SMTPS",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
}


def _level_from_service_name(svc: str) -> Optional[PortAssessment]:
    """
    Tenta di classificare il rischio partendo solo dal nome del servizio.

    Args:
        svc (str): Nome del servizio rilevato (es. "ms-wbt-server", "http", "ssh").

    Returns:
        Optional[PortAssessment]: Oggetto PortAssessment con `port=-1` se il servizio
        è riconosciuto come pericoloso o atteso; None se non è stato possibile
        determinare il livello dal solo nome.
    """

    s = (svc or "").lower()
    danger_keys = [
        ("telnet", "Telnet esposto"),
        ("ms-wbt", "RDP esposto"),
        ("rdp", "RDP esposto"),
        ("vnc", "VNC esposto"),
        ("smb", "SMB esposto"),
        ("microsoft-ds", "SMB esposto"),
        ("nfs", "NFS esposto"),
        ("ftp", "FTP esposto"),
        ("tftp", "TFTP esposto"),
        ("mysql", "MySQL esposto"),
        ("postgres", "PostgreSQL esposto"),
        ("mongodb", "MongoDB esposto"),
        ("redis", "Redis esposto"),
        ("elasticsearch", "Elasticsearch esposto"),
        ("docker", "Docker API esposta"),
        ("kubelet", "Kubelet API esposta"),
        ("x11", "X11 esposto"),
    ]
    expected_keys = [
        ("http", "HTTP/HTTPS pubblico"),
        ("ssl/http", "HTTPS pubblico"),
        ("ssh", "SSH (amministrazione)"),
        ("smtp", "Mail (SMTP)"),
        ("imap", "Mail (IMAP)"),
        ("pop3", "Mail (POP3)"),
        ("domain", "DNS"),
        ("dns", "DNS"),
    ]
    for key, reason in danger_keys:
        if key in s:
            return PortAssessment(-1, svc, "danger", COLORS["danger"], reason)
    for key, reason in expected_keys:
        if key in s:
            return PortAssessment(-1, svc, "expected", COLORS["expected"], reason)
    return None


def classify_port(port: int, service: Optional[str]):
    """
    Classifica una porta (e relativo servizio) in base al livello di rischio.

    Args:
        port (int): Numero di porta da classificare
        service (str): Nome del servizio rilevato

    Returns:
        PortAssessment: Valutazione completa della porta con livello, colore e motivazione
    """

    if port in DANGEROUS_PORTS:
        return PortAssessment(
            port,
            service or "",
            "danger",
            COLORS["danger"],
            DANGEROUS_PORTS[port],
        )
    if port in EXPECTED_PORTS:
        return PortAssessment(
            port,
            service or "",
            "expected",
            COLORS["expected"],
            EXPECTED_PORTS[port],
        )

    by_name = _level_from_service_name(service or "")
    if by_name:
        return PortAssessment(
            port,
            service or "",
            by_name.level,
            COLORS[by_name.level],
            by_name.reason,
        )

    level = "caution" if port < 1024 else "unknown"
    reason = "Servizio su porta privilegiata" if level == "caution" else "Non classificato"
    return PortAssessment(port, service or "", level, COLORS[level], reason)
