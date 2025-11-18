import html
import json
import re
import requests
import cve_searchsploit as CS
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#Regex per individuare pattern CVE-YYYY-NNNN in testo libero
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
#Endpoint base delle API NVD 2.0
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEDetail:
    """
    Rappresentazione CVE ottenuto da NVD.

    Attributes:
        cve (str): Identificatore del CVE
        score (float): Punteggio CVSS base associato al CVE
        severity (str): Gravità
        vector (str): Vector string CVSS
        published (str): Data di pubblicazione del CVE
        last_modified (str): Data di ultima modifica del CVE
        description (str): Descrizione testuale del problema.
    """

    cve: str
    score: Optional[float] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    description: Optional[str] = None


class CVESearcher:
    """
    Gestisce la risoluzione e l'arricchimento dei CVE a partire da exploit di exploit-db.

    Dato un elenco di tuple (title, edb_id), la pipeline è:
      1) Risoluzione dei CVE per ogni EDB-ID (mapping locale -> pagina EDB -> RAW -> fallback sul titolo).
      2) Interrogazione delle API NVD 2.0 per ottenere CVSS/Severity e metadati del CVE.
      3) Ritorno di:
         - una lista di righe arricchite pronte per il report,
         - un mapping CVE -> CVEDetail con i dettagli completi.

    Args:
        session (Optional[requests.Session]): Sessione HTTP riutilizzabile; se None ne crea una se possibile.
        nvd_api_key (Optional[str]): Chiave API per le richieste alle API NVD (opzionale ma consigliata).
        connect_timeout (int): Timeout di connessione per le richieste HTTP.
        read_timeout (int): Timeout di lettura per le richieste HTTP.
        workers (int): Numero di worker del ThreadPoolExecutor per lo scraping parallelo.
        max_page_fetches (int): Numero massimo di pagine EDB da scaricare per risolvere CVE mancanti.
        debug (bool): Se True, stampa log di debug su stdout.
    """

    def __init__(
        self,
        session: Optional["requests.Session"] = None,
        nvd_api_key: Optional[str] = None,
        connect_timeout: int = 5,
        read_timeout: int = 10,
        workers: int = 6,
        max_page_fetches: int = 12,
        debug: bool = False,
    ) -> None:
        self.debug = bool(debug)
        self.nvd_api_key = nvd_api_key
        self.timeout = (connect_timeout, read_timeout)
        self.workers = max(1, int(workers))
        self.max_page_fetches = max(0, int(max_page_fetches))

        self.session = session or (requests.Session() if requests else None)
        if self.session:
            try:
                from requests.adapters import HTTPAdapter
                from urllib3.util.retry import Retry
                #Configura retry automatici di base per errori/transienti HTTP
                adapter = HTTPAdapter(
                    max_retries=Retry(
                        total=2,
                        connect=2,
                        read=2,
                        backoff_factor=0.3,
                        status_forcelist=[429, 500, 502, 503, 504],
                    )
                )
                self.session.mount("https://", adapter)
            except Exception:
                pass
            try:
                self.session.headers.update({
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8",
                })
                if self.nvd_api_key:
                    self.session.headers.setdefault("apiKey", self.nvd_api_key)
            except Exception:
                pass

        #cache EDB-ID -> lista CVE
        self._edb_cve_cache: Dict[int, List[str]] = {}
        #cache CVE -> CVEDetail
        self._nvd_cache: Dict[str, CVEDetail] = {}


    def _http_get_text(self, url):
        """
        Effettua una richiesta HTTP GET e restituisce il corpo testuale della risposta.

        Args:
            url (str): URL da richiedere

        Returns:
            str: Testo della risposta se disponibile, altrimenti None
        """

        if self.session:
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.ok and r.text:
                    return r.text
                if self.debug:
                    print(f"[cve] requests GET {url} -> {r.status_code}")
            except Exception as e:
                if self.debug:
                    print(f"[cve] requests GET error {url}: {e}")

        #fallback urllib
        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8",
                },
            )
            with urllib.request.urlopen(req, timeout=sum(self.timeout)) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as e:
            if self.debug:
                print(f"[cve] urllib GET error {url}: {e}")
        return None

    def _http_get_json(self, url, params):
        """
        Effettua una richiesta HTTP GET e restituisce la risposta JSON decodificata.

        Args:
            url (str): URL di destinazione.
            params (Dict[str, str]): Parametri di query per la richiesta.

        Returns:
            Optional[dict]: Oggetto JSON decodificato se disponibile, altrimenti None.
        """

        #NVD
        if self.session:
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                if r.status_code == 429:
                    import time as _t
                    _t.sleep(1.0)
                    r = self.session.get(url, params=params, timeout=self.timeout)
                if r.ok:
                    return r.json()
                if self.debug:
                    print(f"[cve] requests GET JSON {url} -> {r.status_code}")
            except Exception as e:
                if self.debug:
                    print(f"[cve] requests GET JSON error {url}: {e}")

        try:
            import urllib.parse, urllib.request
            qs = urllib.parse.urlencode(params)
            req = urllib.request.Request(
                f"{url}?{qs}",
                headers={"User-Agent": "python-urllib/3 cve-searcher"},
            )
            with urllib.request.urlopen(req, timeout=sum(self.timeout)) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:
            if self.debug:
                print(f"[cve] urllib GET JSON error {url}: {e}")
        return None

   

    def enrich(self, title_edbr):
        """
        Arricchisce le informazioni sugli exploit EDB con i relativi CVE e metadati NVD.

        A partire da una sequenza di tuple (title, edb_id), risolve i CVE associati
        ad ogni EDB-ID (usando mapping locale, pagina EDB, contenuto RAW e titolo) e
        recupera i dettagli da NVD (punteggio CVSS, severity, descrizione...)

        Args:
            title_edb (Sequence[Tuple[str, int]]): Sequenza di tuple (titolo, exploit-db ID)

        Returns:
            Tuple[List[Dict[str, object]], Dict[str, CVEDetail]]: Una tupla composta da:
                - lista di dizionari, uno per exploit, contenente:
                    * edb_id (int): ID exploit-db
                    * title (str): Titolo dell'exploit
                    * cves (List[str]): Lista di CVE associati.
                    * max_cvss (Optional[float]): Punteggio CVSS massimo tra i CVE associati
                    * max_severity (Optional[str]): Gravità massima tra i CVE associati
                    * url (str): URL della pagina exploit-db
                - dizionario che mappa ogni CVE a un oggetto CVEDetail.
        """

        edb_to_title: Dict[int, str] = {}
        for title, edb in title_edbr:
            try:
                edb = int(edb)
            except Exception:
                continue
            if edb > 0 and edb not in edb_to_title:
                edb_to_title[edb] = str(title or "").strip()

        edb_cves = self._resolve_cves_for_many(edb_to_title)

        all_cves: List[str] = []
        for cves in edb_cves.values():
            all_cves.extend(cves)
        cve_details = self._fetch_nvd_batch(all_cves)

        rows: List[Dict[str, object]] = []
        for edb_id, title in edb_to_title.items():
            cves = edb_cves.get(edb_id, [])
            max_score: Optional[float] = None
            max_sev: Optional[str] = None
            for c in cves:
                det = cve_details.get(c)
                if det and det.score is not None:
                    if max_score is None or float(det.score) > float(max_score):
                        max_score = float(det.score)
                        max_sev = det.severity
            rows.append({
                "edb_id": edb_id,
                "title": title,
                "cves": cves,
                "max_cvss": max_score,
                "max_severity": max_sev,
                "url": f"https://www.exploit-db.com/exploits/{edb_id}",
            })

        rows.sort(key=lambda r: (-(r["max_cvss"] or -1.0), -int(r["edb_id"])))
        return rows, cve_details

    def _resolve_cves_for_many(self, edb_to_title):
        """
        "Resolving" i CVE associati a più exploit EDB in un solo passaggio

        Args:
            edb_to_title (Dict[int, str]): Mapping exploit-db ID -> titolo exploit

        Returns:
            Dict[int, List[str]]: Mapping exploit-db ID -> lista di CVE
        """

        if not edb_to_title:
            return {}

        out: Dict[int, List[str]] = {}
        unresolved: List[int] = []

        for edb_id, title in edb_to_title.items():
            cached = self._edb_cve_cache.get(edb_id)
            if cached is not None:
                out[edb_id] = cached
                continue

            cves: List[str] = []
            if CS is not None:
                try:
                    m = CS.cve_from_edbid(int(edb_id))  # type: ignore
                    if m:
                        cves = sorted({str(c).upper() for c in m})
                        if self.debug:
                            print(f"[cve] CS map EDB {edb_id}: {cves}")
                except Exception as e:
                    if self.debug:
                        print(f"[cve] CS error EDB {edb_id}: {e}")

            if not cves:
                #fallback dal titolo
                cves = self._extract_cves(title)
                if self.debug and cves:
                    print(f"[cve] title match EDB {edb_id}: {cves}")

            if cves:
                self._edb_cve_cache[edb_id] = cves
                out[edb_id] = cves
            else:
                unresolved.append(edb_id)

        #scraping pagina/raw se possibile
        if unresolved and self.max_page_fetches > 0:
            targets = unresolved[: self.max_page_fetches]

            def task(_id):
                """
                Risolve i CVE per un singolo exploit EDB tramite scraping pagina e RAW.

                Args:
                    _id (int): Identificatore exploit-db.

                Returns:
                    Tuple[int, List[str]]: Coppia (edb_id, lista CVE trovati).
                """
                cves = self._fetch_cves_from_edb_page(_id)
                if not cves:
                    cves = self._fetch_cves_from_raw(_id)
                cves = cves or []
                self._edb_cve_cache[_id] = cves
                return _id, cves

            try:
                with ThreadPoolExecutor(max_workers=self.workers) as ex:
                    futs = {ex.submit(task, i): i for i in targets}
                    for fut in as_completed(futs):
                        edb_id, cves = fut.result()
                        out[edb_id] = cves
                        if self.debug:
                            print(f"[cve] fetched EDB {edb_id}: {cves}")
            except Exception:
                #fallback sequenziale se il ThreadPoolExecutor fallisce
                for i in targets:
                    edb_id, cves = task(i)
                    out[edb_id] = cves
                    if self.debug:
                        print(f"[cve] fetched EDB {edb_id} (seq): {cves}")

        for edb_id in edb_to_title:
            out.setdefault(edb_id, [])
        return out

    def _extract_cves(self, text):
        """
        Estrae tutti i pattern CVE-YYYY-NNNN da una stringa.

        Args:
            text (str): Testo da analizzare.

        Returns:
            List[str]: Lista ordinata e deduplicata di CVE trovati nel testo.
        """

        return sorted({m.upper() for m in CVE_RX.findall(text or "")})

    def _fetch_cves_from_edb_page(self, edb_id):
        """
        Estrae i CVE dalla pagina HTML di un exploit su exploit-db.

        La funzione scarica la pagina dell'exploit e cerca CVE in:
          - contenuto HTML generale
          - meta tag (content)
          - link verso NVD/MITRE che contengono il CVE
          - sezioni 'CVE' 

        Args:
            edb_id (int): Identificatore exploit-db dell'exploit

        Returns:
            List[str]: Lista ordinata e deduplicata di CVE estratti dalla pagina
        """

        url = f"https://www.exploit-db.com/exploits/{int(edb_id)}"
        html_text = self._http_get_text(url)
        if not html_text:
            return []

        found: set[str] = set()

        #match 'CVE-YYYY-NNNN' ovunque
        for m in CVE_RX.findall(html_text):
            found.add(m.upper())

        #meta/og/keywords/description
        for meta_content in re.findall(r'<meta[^>]+content=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            for m in CVE_RX.findall(meta_content):
                found.add(m.upper())

        #href verso NVD/MITRE con CVE nell'URL
        for m in re.findall(
            r'href=["\']https?://(?:nvd\.nist\.gov|cve\.mitre\.org)[^"\']*?(CVE-\d{4}-\d{4,7})',
            html_text, flags=re.IGNORECASE
        ):
            found.add(m.upper())

        #blocco "CVE"
        for m in re.finditer(
            r"CVE\s*:\s*</h4>\s*<h6[^>]*>.*?(\d{4}-\d{4,7})",
            html_text,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            found.add(f"CVE-{m.group(1).upper()}")

        #Sezione di fallback
        if not found:
            for m in re.finditer(r"CVE\s*:\s*", html_text, re.IGNORECASE):
                span = html_text[m.end(): m.end() + 5000]
                for n in re.findall(r"\b\d{4}-\d{4,7}\b", span):
                    found.add(f"CVE-{n.upper()}")

        return sorted(found)

    def _fetch_cves_from_raw(self, edb_id):
        """
        Estrae i CVE dal contenuto RAW di un exploit su exploit-db.

        Se la pagina HTML non contiene riferimenti chiari a CVE, come fallback
        la funzione scarica il contenuto RAW e applica la regex CVE.

        Args:
            edb_id (int): Identificatore exploit-db dell'exploit

        Returns:
            List[str]: Lista ordinata e deduplicata di CVE trovati nel contenuto RAW.
        """

        url = f"https://www.exploit-db.com/raw/{int(edb_id)}"
        txt = self._http_get_text(url)
        return self._extract_cves(txt or "")

    def _fetch_nvd_batch(self, cves):
        """
        Recupera i dettagli NVD per un insieme di CVE, con caching semplice.

        Per ogni CVE:
          - se è già presente in cache, viene usato il valore cache,
          - altrimenti viene invocato `_fetch_nvd_single` e il risultato viene memorizzato.

        Args:
            cves (Iterable[str]): Collezione di stringhe CVE (es. "CVE-2024-12345").

        Returns:
            Dict[str, CVEDetail]: Mapping CVE -> CVEDetail con i dettagli NVD.
        """

        uniq = sorted({c for c in (c.upper() for c in cves) if c.startswith("CVE-")})
        if not uniq:
            return {}
        out: Dict[str, CVEDetail] = {}
        for cve in uniq:
            if cve in self._nvd_cache:
                out[cve] = self._nvd_cache[cve]
                continue
            det = self._fetch_nvd_single(cve)
            self._nvd_cache[cve] = det
            out[cve] = det
        return out

    def _fetch_nvd_single(self, cve):
        """
        Recupera i dettagli NVD per un singolo CVE tramite le API NVD 2.0

        Args:
            cve (str): Identificatore CVE 

        Returns:
            CVEDetail: Oggetto con i dettagli del CVE; se la richiesta fallisce, contiene solo il campo "cve"
        """

        data = self._http_get_json(NVD_BASE_URL, {"cveId": cve})
        if not data:
            return CVEDetail(cve=cve)

        try:
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return CVEDetail(cve=cve)
            cv = vulns[0].get("cve", {})
            descs = cv.get("descriptions", []) or []
            description: Optional[str] = None
            if descs:
                en = [d for d in descs if d.get("lang") == "en"]
                description = (en[0] if en else descs[0]).get("value")

            metrics = cv.get("metrics", {}) or {}
            score = None
            severity = None
            vector = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if arr:
                    m = arr[0]
                    d = m.get("cvssData", {})
                    score = d.get("baseScore") or m.get("baseScore")
                    severity = (d.get("baseSeverity") or m.get("baseSeverity")) or severity
                    vector = d.get("vectorString") or d.get("vector") or vector
                    break

            return CVEDetail(
                cve=cve,
                score=float(score) if score is not None else None,
                severity=str(severity) if severity is not None else None,
                vector=str(vector) if vector is not None else None,
                published=cv.get("published"),
                last_modified=cv.get("lastModified"),
                description=description,
            )
        except Exception:
            return CVEDetail(cve=cve)