import html
from typing import Dict, List, Optional, Sequence, Tuple

from .cve_searcher import CVEDetail
from .web import WhatWebResult
from .port_risk import classify_port
from .templates import T
from core.templates import *
from pathlib import Path
import html


def _esc(x):
    """
    Effettua l'escape HTML sicuro di un valore generico.


    Args:
        x (object): Valore da convertire ed "escapare".

    Returns:
        str: Stringa con escape HTML applicato.
    """

    return html.escape(str(x if x is not None else ""))


def _sev_color(sev: Optional[str]) -> str:
    """
    Restituisce il colore HTML corrispondente a un livello di severità NVD.

    I livelli sono:
      - CRITICAL
      - HIGH
      - MEDIUM
      - LOW
      - NONE

    Args:
        sev (Optional[str]): Stringa di severità

    Returns:
        str: Codice colore esadecimale
    """

    s = (sev or "").upper()
    return {
        "CRITICAL": "#b11a1a",
        "HIGH": "#d0471b",
        "MEDIUM": "#d09d1b",
        "LOW": "#2b7b2b",
        "NONE": "#1b6ad0",
    }.get(s, "#555")

_HTTP_PORTS = {80, 8080, 8000, 8888, 81}
_HTTPS_PORTS = {443, 8443, 9443, 4443}

# guessing minimo per servizi comuni (se Nmap non li ha evidenziati)
_GUESS_SERVICE_BY_PORT = {
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    27017: "mongodb",
}

_HTTP_SERVER_VENDORS = {
    "apache",
    "nginx",
    "microsoft-iis",
    "litespeed",
    "openresty",
    "caddy",
    "varnish",
    "haproxy",
    "squid",
}

# mapping tra nome servizio e keyword da cercare nelle coppie Nmap
_HTTP_SERVER_KEYWORDS = list(_HTTP_SERVER_VENDORS)
_KW_BY_SERVICE = {
    "ssh": ["openssh"],
    "mysql": ["mysql"],
    "postgres": ["postgres", "postgresql"],
    "postgresql": ["postgres", "postgresql"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "vnc": ["vnc"],
    "ms-wbt-server": ["rdp", "ms-wbt", "windows terminal"],
    "smb": ["samba", "microsoft-ds", "smb"],
    "ftp": ["ftp"],
    "telnet": ["telnet"],
    "dns": ["bind", "named", "dns"],
    "imap": ["imap"],
    "pop3": ["pop3"],
    "smtp": ["postfix", "exim", "sendmail", "smtp"],
    "http": _HTTP_SERVER_KEYWORDS,
    "https": _HTTP_SERVER_KEYWORDS,
}


def _guess_service(port, svc):
    """
    Tenta di determinare il nome del servizio associato a una porta.

    Usa il valore riportato da Nmap, se presente e non vuoto; altrimenti
    prova a indovinare il servizio dalla porta

    Args:
        port (int): Numero di porta aperta.
        svc (str): Nome servizio riportato da Nmap (può essere vuoto o "-").

    Returns:
        str: Nome servizio normalizzato oppure "-" se non determinabile.
    """

    svc = (svc or "").strip()
    if svc and svc != "-":
        return svc
    return _GUESS_SERVICE_BY_PORT.get(int(port), "-")


def _find_http_server_from_whatweb(ww_versions):
    """
    Trova, se presente, il server HTTP principale a partire dalle versioni WhatWeb.

    Cerca nella lista di coppie (tecnologia, versione) una tecnologia
    che corrisponda a un HTTP server noto (Apache, Nginx, IIS, ...).

    Args:
        ww_versions (Optional[Sequence[Tuple[str, str]]]): Sequenza di tuple
            (nome_tecnologia, versione) estratte da WhatWeb.

    Returns:
        Optional[Tuple[str, str]]: Tuple (tecnologia, versione) se trovata,
        altrimenti None.
    """

    if not ww_versions:
        return None
    for tech, ver in ww_versions:
        if (tech or "").lower() in _HTTP_SERVER_VENDORS:
            return tech, ver
    return None


def _enrich_from_pairs(svc_lower: str, pairs):
    """
    Cerca una tecnologia coerente con il servizio in una lista di coppie (product, version)

    Args:
        svc_lower (str): Nome del servizio in minuscolo (es. "ssh", "http").
        pairs (Optional[Sequence[Tuple[str, str]]]): Sequenza di coppie
            (product, version) tipicamente provenienti da Nmap o WhatWeb.

    Returns:
        Optional[Tuple[str, str]]: Coppia (product, version) se viene trovato
        un match, altrimenti None.
    """

    if not pairs or not svc_lower:
        return None
    kws = _KW_BY_SERVICE.get(svc_lower)
    if not kws:
        kws = [svc_lower]  # match generico sul nome servizio
    for prod, ver in pairs:
        pl = (prod or "").lower()
        if any(kw in pl for kw in kws):
            return prod or "", ver or ""
    return None


def _fmt_prod_ver(prod, ver):
    """
    Formattta una coppia (product, version) in una stringa pronta per l'HTML

    Args:
        prod (Optional[str]): Nome prodotto/tecnologia
        ver (Optional[str]): Versione

    Returns:
        str: Stringa formattata ed "escapata" per l'HTML.
    """

    if prod and ver:
        return f"{_esc(prod)} {_esc(ver)}"
    return _esc(prod) if prod else (_esc(ver) if ver else "—")


def build_open_ports_section(open_ports,title = "Porte aperte e servizi",*,whatweb_versions,
nmap_pairs_for_enrichment = None,):
    """
    Costruisce la sezione HTML relativa alle porte aperte e ai servizi rilevati.

    Per ogni porta:
      - determina il servizio (da Nmap o considerando la porta)
      - arricchisce prodotto/versione con dati WhatWeb ed Nmap
      - calcola il livello di rischio
      - genera una riga della tabella HTML con badge di rischio e motivazione

    Args:
        open_ports (Sequence[Dict[str, object]]): Sequenza di dict con almeno:
            - port (int): Numero di porta.
            - proto (str): Protocollo (es. 'tcp').
            - service (str, opzionale): Nome del servizio.
            - product (str, opzionale): Nome prodotto/tecnologia.
            - version (str, opzionale): Versione del prodotto.
        title (str): Titolo della sezione.
        whatweb_versions (Optional[Sequence[Tuple[str, str]]]): Coppie
            (tecnologia, versione) estratte da WhatWeb per arricchire HTTP/HTTPS.
        nmap_pairs_for_enrichment (Optional[Sequence[Tuple[str, str]]]): Coppie
            (product, version) usate come fallback per arricchire i servizi.

    Returns:
        str: Stringa HTML contenente l'intera sezione "Porte aperte e servizi".
    """

    parts: List[str] = []
    parts.append(TPL_H2.format(text=_esc(title)))

    if not open_ports:
        parts.append(TPL_OPEN_PORTS_EMPTY)
        return "".join(parts)

    emoji = {"expected": "🟢", "caution": "🟡", "danger": "🔴", "unknown": "⚪"}

    rows: List[str] = []
    rows.append(TPL_OPEN_PORTS_TABLE_OPEN)

    for p in sorted(open_ports, key=lambda x: (int(x.get("port", 0)), str(x.get("proto", "")))):
        port = int(p.get("port"))
        proto = (p.get("proto") or "tcp").lower()
        svc0 = (p.get("service") or "").strip()
        prod0 = (p.get("product") or "").strip()
        ver0 = (p.get("version") or "").strip()

        #Servizio (usa Nmap, altrimenti guess da porta)
        svc = _guess_service(port, svc0)
        svc_lower = (svc or "").lower()

        #Prodotto/versione con Nmap
        prod, ver = prod0, ver0

        #HTTP/HTTPS: prova da WhatWeb (vendor/version) se Nmap non ha dato nulla
        if (not prod and not ver) and (
            svc_lower.startswith("http") or port in _HTTP_PORTS or port in _HTTPS_PORTS
        ):
            http_sv = _find_http_server_from_whatweb(whatweb_versions)
            if http_sv:
                prod, ver = http_sv

        #fallback generale: cerca in tutte le coppie disponibili (Nmap + WhatWeb)
        if not prod and not ver:
            candidate_pairs: List[Tuple[str, str]] = list(nmap_pairs_for_enrichment or [])
            if whatweb_versions:
                candidate_pairs.extend(list(whatweb_versions))
            pv = _enrich_from_pairs(svc_lower, candidate_pairs)
            if pv:
                prod, ver = pv

        assess = classify_port(port, None if svc in ("", "-") else svc)
        badge = "<span class='badge' style='background:{bg}'>{emoji} {lvl}</span>".format(
            bg=assess.color, emoji=emoji[assess.level], lvl=assess.level
        )

        rows.append(
            TPL_OPEN_PORTS_ROW.format(
                port=_esc(port),
                proto=_esc(proto),
                service=_esc(svc or "-"),
                prodver=_fmt_prod_ver(prod, ver),
                risk_badge=badge,
                reason=_esc(assess.reason),
            )
        )

    rows.append(TPL_OPEN_PORTS_TABLE_CLOSE)
    parts.extend(rows)
    parts.append(TPL_RISK_LEGEND)
    return "".join(parts)


def build_cve_section(rows,cve_details,title = "Exploit → CVE (con score NVD)"):
    """
    Costruisce la sezione HTML relativa agli exploit e ai CVE associati.

    Args:
        rows (List[Dict[str, object]]): Risultati arricchiti, tipicamente
            prodotti da `CVESearcher.enrich`, contenenti:
              * edb_id, title, cves, max_cvss, max_severity, ...
        cve_details (Dict[str, CVEDetail]): Mapping CVE -> dettagli NVD.
        title (str): Titolo della sezione.

    Returns:
        str: Stringa HTML della sezione "Exploit → CVE".
    """

    #ordina per rischio: max_cvss DESC, poi EDB-ID DESC
    rows_sorted = sorted(
        rows, key=lambda r: (-(r.get("max_cvss") or -1.0), -int(r.get("edb_id") or 0))
    )

    parts: List[str] = []
    parts.append(TPL_H2.format(text=_esc(title)))
    if not rows_sorted:
        parts.append(TPL_CVE_EMPTY)
        return "".join(parts)

    parts.append(TPL_CVE_TABLE_OPEN)

    for r in rows_sorted:
        edb = int(r.get("edb_id") or 0)
        url = f"https://www.exploit-db.com/exploits/{edb}" if edb else ""
        cves = list(r.get("cves") or [])
        cves_html: List[str] = []
        for c in cves:
            det = cve_details.get(str(c))
            tip = []
            if det and det.score is not None:
                tip.append(f"CVSS {det.score}")
            if det and det.severity:
                tip.append(det.severity)
            title_attr = _esc(" · ".join(tip)) if tip else ""
            cves_html.append(
                f"<a class='pill' href='https://nvd.nist.gov/vuln/detail/{_esc(c)}' "
                f"target='_blank' rel='noopener' title='{title_attr}'>{_esc(c)}</a>"
            )

        sev = r.get("max_severity") or "Unknown"
        color = _sev_color(str(sev))
        sev_badge = f"<span class='badge' style='background:{color}'>{_esc(sev)}</span>"
        max_cvss = r.get("max_cvss")
        cvss_str = f"{max_cvss:.1f}" if isinstance(max_cvss, (int, float)) else "—"

        parts.append(
            TPL_CVE_ROW.format(
                edb_url=_esc(url),
                edb=_esc(edb),
                title=_esc(r.get("title")),
                cves_html=("".join(cves_html) if cves_html else "<span class=muted>—</span>"),
                max_cvss=_esc(cvss_str),
                sev_badge=sev_badge,
            )
        )

    parts.append(TPL_CVE_TABLE_CLOSE)
    return "".join(parts)


def build_whatweb_section( results, title = "WhatWeb - Output grezzo"):
    """
    Costruisce una sezione HTML di debug con l'output grezzo di WhatWeb

    Args:
        results (Sequence[WhatWebResult]): Sequenza di risultati di WhatWeb
            contenenti target, cmd, stdout, stderr e returncode.
        title (str): Titolo della sezione di debug.

    Returns:
        str: Stringa HTML contenente i dettagli grezzi di WhatWeb.
    """

    parts: List[str] = []
    parts.append(TPL_WW_WRAP_OPEN.format(title=_esc(title)))

    if not results:
        parts.append(TPL_WW_WRAP_EMPTY)
        return "".join(parts)

    for r in results:
        status = "ok" if r.returncode in (0, 1) else "fail"
        sym = "✓" if status == "ok" else "⚠"

        parts.append(TPL_WW_DETAILS_OPEN)

        summary_inner = TPL_WW_SUMMARY.format(
            sym=sym,
            status=status,
            target=_esc(r.target),
            code=r.returncode,
        )
        parts.append(TPL_WW_SUMMARY_WRAP.format(inner=summary_inner))
        parts.append(TPL_WW_BODY_OPEN)

        parts.append(TPL_WW_ROW_CMD.format(cmd=_esc(r.cmd)))
        parts.append(
            TPL_WW_ROW_STDOUT.format(
                stdout=_esc(r.stdout) if (r.stdout or "").strip() else "—"
            )
        )

        if (r.stderr or "").strip():
            parts.append(TPL_WW_ROW_STDERR.format(stderr=_esc(r.stderr)))

        parts.append(TPL_WW_BODY_CLOSE)
        parts.append(TPL_WW_DETAILS_CLOSE)

    parts.append(TPL_WW_WRAP_CLOSE)
    return "".join(parts)


def build_whatweb_versions_section( whatweb_versions, title = "Tecnologie (WhatWeb)",):
    """
    Costruisce una sezione HTML delle tecnologie web usate individuate da WhatWeb.


    Args:
        whatweb_versions (Sequence[Tuple[str, str]]): Sequenza di tuple
            (tecnologia, versione) estratte da WhatWeb.
        title (str): Titolo della sezione.

    Returns:
        str: Stringa HTML con l'elenco delle tecnologie rilevate.
    """

    parts: List[str] = []
    parts.append(TPL_H2.format(text=_esc(title)))
    if not whatweb_versions:
        parts.append(TPL_WW_TECH_EMPTY)
        return "".join(parts)

    parts.append(TPL_WW_TECH_WRAP_OPEN)
    for tech, ver in whatweb_versions:
        parts.append(TPL_WW_TECH_ITEM.format(tech=_esc(tech), ver=_esc(ver)))
    parts.append(TPL_WW_TECH_WRAP_CLOSE)
    return "".join(parts)


def build_full_report(
    cve_rows, cve_details, whatweb_results, title = "Vulnerability Report", *,
    services_for_exploit = None, whatweb_versions = None, show_raw_whatweb = True, open_ports = None,):
    """
    Unisce tutte le sezioni e genera l'intero report HTML come stringa.

    Args:
        cve_rows (List[Dict[str, object]]): Righe exploit/CVE arricchite per il report.
        cve_details (Dict[str, CVEDetail]): Mapping CVE -> dettagli NVD.
        whatweb_results (Sequence[WhatWebResult]): Output grezzi di WhatWeb per ogni target.
        title (str): Titolo principale del report HTML.
        services_for_exploit (Optional[Sequence[Tuple[str, str]]]): Coppie
            (product, version) usate per arricchire la tabella porte.
        whatweb_versions (Optional[Sequence[Tuple[str, str]]]): Coppie
            (tecnologia, versione) da WhatWeb per arricchire il report.
        show_raw_whatweb (bool): Se True, mostra la sezione di debug con output grezzo.
        open_ports (Optional[Sequence[Dict[str, object]]]): Lista di porte/servizi aperti,
            da passare a `build_open_ports_section`.

    Returns:
        str: Documento HTML completo del report di vulnerabilità.
    """

    head = TPL_HEAD.format(title=_esc(title), css=BASE_CSS)
    parts = [TPL_HTML_START.format(head=head), TPL_H1.format(text=_esc(title))]

    #Porte Aperte
    if open_ports is not None:
        parts.append(
            build_open_ports_section(
                list(open_ports),
                whatweb_versions=list(whatweb_versions or []),
                nmap_pairs_for_enrichment=list(services_for_exploit or []),
            )
        )

    #WhatWeb
    if whatweb_versions is not None:
        parts.append(build_whatweb_versions_section(list(whatweb_versions)))

    #Exploit & CVE
    parts.append(build_cve_section(cve_rows, cve_details))

    #WhatWeb grezzo
    if show_raw_whatweb and whatweb_results:
        parts.append(build_whatweb_section(whatweb_results))

    parts.append(TPL_HTML_END)
    return "".join(parts)


def write_full_report(
    output_path,cve_rows,cve_details,whatweb_results,title= "Vulnerability Report",
    *,services_for_exploit = None,whatweb_versions = None,show_raw_whatweb = True,
    open_ports = None):
    """
    Genera il report HTML completo e lo salva su disco nel percorso indicato

    Args:
        output_path (str): Percorso di output del file HTML da generare.
        cve_rows (List[Dict[str, object]]): Righe exploit/CVE arricchite.
        cve_details (Dict[str, CVEDetail]): Dettagli NVD per ogni CVE.
        whatweb_results (Sequence[WhatWebResult]): Output grezzo di WhatWeb.
        title (str): Titolo del report.
        services_for_exploit (Optional[Sequence[Tuple[str, str]]]): Coppie
            (product, version) per arricchire la tabella porte.
        whatweb_versions (Optional[Sequence[Tuple[str, str]]]): Coppie
            (tecnologia, versione) di WhatWeb per sezione dedicata/arricchimento.
        show_raw_whatweb (bool): Se True, include la sezione debug con output WhatWeb.
        open_ports (Optional[Sequence[Dict[str, object]]]): Porte aperte da riportare nel report.

    Returns:
        str: Percorso assoluto del file HTML generato.
    """

    html_doc = build_full_report(
        cve_rows=cve_rows,
        cve_details=cve_details,
        whatweb_results=whatweb_results,
        title=title,
        services_for_exploit=services_for_exploit,
        whatweb_versions=whatweb_versions,
        show_raw_whatweb=show_raw_whatweb,
        open_ports=open_ports,
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)  #crea la cartella se manca
    with out.open("w", encoding="utf-8") as f:
        f.write(html_doc)
    return str(out)
