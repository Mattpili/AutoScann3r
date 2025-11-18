import os
import re
import datetime
from itertools import chain
from pathlib import Path
from core.nmap_scanner import NmapScanner
from core.ports import extract_nmap
from core.exploit_searcher import (
    find_exploits_same_or_newer,
    extract_title_edb_tuples,
    normalize_services_for_search,
)
from core.cve_searcher import CVESearcher
from core.web import run_whatweb, extract_versions_from_whatweb
from core.reporter import write_full_report


# Root della repository (directory che contiene /core)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Directory per i report, configurabile via variabile d'ambiente AUTOSCANN3R_REPORTS_DIR
_reports_env = os.getenv("AUTOSCANN3R_REPORTS_DIR")
# Directory dei report FUORI da /core (default: ./reports)
_REPORTS_DIR = Path(_reports_env).expanduser() if _reports_env else (_PROJECT_ROOT / "reports")
_REPORTS_DIR = _REPORTS_DIR.resolve()
# Crea a prescindere la cartella "/reports"
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Porte tipiche HTTP/HTTPS
HTTP_PORTS = {80, 8080, 8000, 8888, 81}
HTTPS_PORTS = {443, 8443, 9443, 4443}


def guess_web_targets(ip, ports_csv):
    """
    Costruisce una lista di URL HTTP/HTTPS a partire dalle porte aperte

    Args:
        ip (str): Indirizzo IP del target.
        ports_csv (str): Stringa contenente l'elenco delle porte aperte

    Returns:
        list: Lista di URL HTTP/HTTPS generati dalle porte corrispondenti
    """

    urls = []
    if not ports_csv:
        return urls
    for p in (s.strip() for s in str(ports_csv).split(",") if s.strip()):
        try:
            port = int(p)
        except ValueError:
            continue
        if port in HTTP_PORTS:
            urls.append(f"http://{ip}:{port}")
        if port in HTTPS_PORTS:
            urls.append(f"https://{ip}:{port}")
    return urls


def safe_slug(s):
    """
    Rimuove caratteri non validi e converte gli spazi in underscore, in modo da
    poter usare la stringa come parte di un nome file

    Args:
        s (str): Stringa di input

    Returns:
        str: Stringa da usare come nome file
    """

    s = re.sub(r"\s+", "_", s.strip())
    s = re.sub(r"[^\w\-.]+", "", s, flags=re.UNICODE)
    return s or "target"


def _to_csv(v):
    """
    Converte una collezione di porte in una stringa CSV

    Args:
        v (list/tuple/set): Valore da convertire

    Returns:
        str: stringa di output
    """

    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ",".join(str(int(p)) for p in v)
    return str(v)



def _parse_nmap_human(nmap_txt):
    """
    Cerca le righe con formato tipico delle porte e costruisce una lista
    di dizionari con dettagli su porta, protocollo, servizio, prodotto e versione

    Args:
        nmap_txt (str): Output testuale di Nmap

    Returns:
        list: Lista di dizionari
    """

    ports = []
    if not nmap_txt:
        return ports

    rx = re.compile(
        r"^\s*(\d{1,5})/(tcp|udp)\s+(open(?:\|\w+)?)\s+(\S+)(?:\s+(.*))?$",
        re.MULTILINE,
    )

    for m in rx.finditer(nmap_txt):
        port = int(m.group(1))
        proto = m.group(2)
        state = m.group(3)
        if not state.startswith("open"):
            continue
        service = m.group(4)
        rest = (m.group(5) or "").strip()

        # Euristica per estrarre product/version dalla stringa rimanente
        vm = re.search(r"(\d+(?:\.\d+){0,3}[a-z0-9\-]*)", rest)
        if vm:
            version = vm.group(1)
            product = rest[:vm.start()].strip()
        else:
            version = ""
            product = rest

        ports.append(
            {
                "port": port,
                "proto": proto,
                "service": service,
                "product": product,
                "version": version,
            }
        )
    return ports


def _parse_nmap_grepable(nmap_txt):
    """
    Effettua il parsing dell'output di Nmap

    Args:
        nmap_txt (str): Output grepable di Nmap

    Returns:
        list: Lista di dizionari
    """

    ports = []
    if not nmap_txt:
        return ports

    for line in nmap_txt.splitlines():
        if "Ports:" not in line:
            continue
        try:
            tail = line.split("Ports:", 1)[1].strip()
        except Exception:
            continue

        for item in tail.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split("/")
            
            if len(parts) < 3:
                continue
            port_str, state, proto = parts[0], parts[1], parts[2]
            if not state.startswith("open"):
                continue
            try:
                port = int(port_str)
            except ValueError:
                continue

            service = parts[4] if len(parts) >= 5 else ""
            verfield = parts[6] if len(parts) >= 7 else ""

            #Estrarre product/version
            verfield = verfield.strip()
            product = ""
            version = ""
            if verfield:
                m = re.search(r"(\d+(?:\.\d+){0,3}[a-z0-9\-]*)", verfield)
                if m:
                    version = m.group(1)
                    product = verfield[:m.start()].strip()
                else:
                    product = verfield

            ports.append(
                {
                    "port": port,
                    "proto": proto,
                    "service": service or "-",
                    "product": product,
                    "version": version,
                }
            )
    return ports


def _ports_from_text_only(nmap_txt):
    """
    Seleziona il parser Nmap più adatto in base al contenuto testuale.

    Se l'output contiene 'Host:' e 'Ports:' viene usato il parser grepable,
    altrimenti viene usato il parser human-readable.

    Args:
        nmap_txt (str): Output testuale di Nmap

    Returns:
        list: Lista di dizionari
    """

    if not nmap_txt:
        return []
    if "Host:" in nmap_txt and "Ports:" in nmap_txt:
        res = _parse_nmap_grepable(nmap_txt)
        if res:
            return res
    return _parse_nmap_human(nmap_txt)


def _ports_from_structured(nmap_out):
    """
    Converte l'output strutturato del NmapScanner in righe per il report.

    Args:
        nmap_out (dict | list): Output NmapScanner

    Returns:
        list: Lista di dizionari normalizzata
    """

    rows = []

    def _add(d: dict):
        #Funzione interna per validare e aggiungere una singola porta
        if not isinstance(d, dict):
            return
        #Considera solo porte "open" se presente il campo "state"
        state = str(d.get("state", "open")).lower()
        if state and not state.startswith("open"):
            return
        try:
            port = int(d.get("port"))
        except Exception:
            return
        proto = (d.get("protocol") or "tcp").lower()
        service = (d.get("service_name") or d.get("service") or "-").strip()
        product = (d.get("product") or "").strip()
        version = (d.get("service_version") or d.get("version") or "").strip()
        rows.append(
            {
                "port": port,
                "proto": proto,
                "service": service,
                "product": product,
                "version": version,
            }
        )

    if isinstance(nmap_out, dict):
        _add(nmap_out)
    elif isinstance(nmap_out, list):
        for item in nmap_out:
            _add(item)

    unique = []
    seen = set()
    for r in rows:
        key = (r["port"], r["proto"], r["service"], r["product"], r["version"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    return unique


def _pairs_from_structured(nmap_out):
    """
    Estrae coppie (nome, versione) dall'output strutturato per la ricerca exploit.

    Args:
        nmap_out (dict | list): Output di NmapScanner

    Returns:
        list: Lista di tuple (nome, versione) senza duplicati, in ordine di comparsa
    """

    pairs = []

    def _add(d: dict):
        # Validare e aggiunge una singola coppia
        if not isinstance(d, dict):
            return
        name = (d.get("product") or d.get("service_name") or d.get("service") or "").strip()
        version = (d.get("service_version") or d.get("version") or "").strip()
        if not name:
            return
        pairs.append((name, version))

    if isinstance(nmap_out, dict):
        _add(nmap_out)
    elif isinstance(nmap_out, list):
        for item in nmap_out:
            _add(item)

    #Dedupe preservando l'ordine
    out = []
    seen = set()
    for t in pairs:
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def process_target(nome, target_ip, name_owner, organization_name):
    """
    Esegue l'intera pipeline di scansione e genera il report finale per un singolo target

    Args:
        nome (str): Nome descrittivo del target (usato nel titolo e nel file di report)
        target_ip (str): Indirizzo IP del target da analizzare
        name_owner (str): Nome dell'individuo che ha richiesto la scansione
        organization_name (str): Nome dell'organizzazione per cui è svolta la scansione

    Returns:
        str: Percorso assoluto del file di report HTML generato
    """

    #Acquisizione del timestamp corrente per il nome file e per il titolo del report
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M")

    #Elenco porte aperte (estratte con MASSCAN) da passare a Nmap
    open_ports = extract_nmap(target_ip)
    open_ports_csv = _to_csv(open_ports)

    #Sezione NMAP
    nmap_output = None
    nmap_text = ""
    if open_ports_csv:
        options = f"-A -p {open_ports_csv}"
        scan = NmapScanner(target_ip, options)
        nmap_output = scan.run_scan()

        #Normalizza in testo solo se è stringa o bytes
        if isinstance(nmap_output, (bytes, bytearray)):
            nmap_text = nmap_output.decode("utf-8", "ignore")
        elif isinstance(nmap_output, str):
            nmap_text = nmap_output

    #Porte aperte per il report 
    if isinstance(nmap_output, (list, dict)):
        open_ports_for_report = _ports_from_structured(nmap_output)
    else:
        open_ports_for_report = _ports_from_text_only(nmap_text)

    #Normalizzazione servizi per la ricerca exploit
    services_for_exploit = []
    if isinstance(nmap_output, (list, dict)):
        pairs = _pairs_from_structured(nmap_output)
        services_for_exploit = normalize_services_for_search(pairs)
    elif nmap_text:
        #Ricava coppie da ciò che abbiamo già estratto per il report
        pairs = []
        for r in open_ports_for_report:
            name = r.get("product") or r.get("service") or ""
            version = r.get("version") or ""
            if name:
                pairs.append((name, version))
        services_for_exploit = normalize_services_for_search(pairs)

    #WhatWeb
    web_targets = guess_web_targets(target_ip, open_ports_csv)
    if web_targets:
        ww_results = run_whatweb(
            web_targets,
            aggression=3,
            timeout=60,
            extra_args=["--log-json", "-"],  # JSON su stdout
        )
        whatweb_versions = extract_versions_from_whatweb(ww_results)
    else:
        ww_results = []
        whatweb_versions = []

    #Merge dei servizi per la ricerca exploit
    services_merged = list(
        dict.fromkeys(
            normalize_services_for_search(
                chain(services_for_exploit, whatweb_versions)
            )
        )
    )

    #Exploit
    if services_merged:
        rows_exact = find_exploits_same_or_newer(services_merged, max_per_service=15)
        title_edb = extract_title_edb_tuples(rows_exact)

        #CVE + NVD
        nvd_key = os.getenv("NVD_API_KEY")
        cve = CVESearcher(nvd_api_key=nvd_key, workers=6, max_page_fetches=10)
        rows_cve, cve_details = cve.enrich(title_edb)
    else:
        rows_cve, cve_details = [], {}

    #Costruzione del percorso finale del report HTML
    out_path = _REPORTS_DIR / f"{safe_slug(nome)}_{timestamp}.html"

    #Scrittura del report completo in HTML
    write_full_report(
        output_path=str(out_path),
        cve_rows=rows_cve,
        cve_details=cve_details,
        whatweb_results=ww_results,
        title=(
            f"Vulnerability Report — {nome} — {target_ip} "
            f"richiesto da {name_owner} per {organization_name} in data: {timestamp}"
        ),
        services_for_exploit=services_for_exploit,
        whatweb_versions=whatweb_versions,
        open_ports=open_ports_for_report,
    )

    return str(out_path)
