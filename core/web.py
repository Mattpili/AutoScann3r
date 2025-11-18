import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Iterable, Any
import json
import re


@dataclass
class WhatWebResult:
    """
    Rappresenta il risultato di una singola esecuzione di WhatWeb su un target.

    Attributes:
        target (str): URL o host:porta passato a WhatWeb.
        cmd (str): Comando completo eseguito (inclusi argomenti).
        returncode (int): Codice di ritorno del processo WhatWeb.
        stdout (str): Output standard prodotto da WhatWeb.
        stderr (str): Output di errore prodotto da WhatWeb.
    """

    target: str
    cmd: str
    returncode: int
    stdout: str
    stderr: str


def _to_str(x):
    """
    Converte un valore generico in stringa UTF-8.

    Args:
        x (Any): Valore da convertire in stringa.

    Returns:
        str: Rappresentazione testuale del valore.
    """

    if isinstance(x, (bytes, bytearray)):
        return x.decode("utf-8", "replace")
    return x if isinstance(x, str) else str(x)


def run_whatweb(targets,aggression = 2,timeout = 20,extra_args = None,):
    """
    Esegue WhatWeb per ogni target e restituisce i risultati grezzi

    Args:
        targets (Sequence[str]): Lista di URL o host:porta da analizzare.
        aggression (int): Livello di aggressività di WhatWeb (1–4).
        timeout (int): Timeout massimo per ogni esecuzione, in secondi.
        extra_args (Optional[Sequence[str]]): Argomenti extra da passare a WhatWeb.

    Returns:
        List[WhatWebResult]: Lista di risultati grezzi, uno per target.

    Raises:
        RuntimeError: Se il binario `whatweb` non è presente nel PATH.
    """

    if not shutil.which("whatweb"):
        raise RuntimeError("whatweb non trovato nel PATH. Installa WhatWeb prima di procedere.")

    results: List[WhatWebResult] = []
    for t in targets:
        if not t:
            continue
        args = [
            "whatweb",
            "-a",
            str(max(1, int(aggression))),
            "--color=never",
        ]
        if extra_args:
            args += list(extra_args)
        args.append(str(t))

        try:
            p = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # garantisce str su stdout/stderr
                timeout=max(1, int(timeout)),
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
            results.append(
                WhatWebResult(
                    target=t,
                    cmd=" ".join(args),
                    returncode=int(p.returncode),
                    stdout=_to_str(p.stdout or ""),
                    stderr=_to_str(p.stderr or ""),
                )
            )
        except subprocess.TimeoutExpired as ex:
            results.append(
                WhatWebResult(
                    target=t,
                    cmd=" ".join(args),
                    returncode=124,
                    stdout=_to_str(getattr(ex, "stdout", "") or ""),
                    stderr=(
                        (_to_str(getattr(ex, "stderr", "") or ""))
                        + ("\n" if getattr(ex, "stderr", "") else "")
                        + "[!] Timeout scaduto"
                    ),
                )
            )
        except Exception as ex:
            results.append(
                WhatWebResult(
                    target=t,
                    cmd=" ".join(args),
                    returncode=1,
                    stdout="",
                    stderr=f"[!] Errore di esecuzione: {ex}",
                )
            )

    return results



VERSION_RX_WW = re.compile(r"\d+(?:\.\d+){0,3}")
SERVER_TOKEN_RX = re.compile(r"([A-Za-z][A-Za-z0-9\-]{1,})/(\d+(?:\.\d+){0,3})")

#Plugin da ignorare
IGNORED_PLUGINS = {
    "IP",
    "Country",
    "Title",
    "HTML5",
    "Script",
    "Favicon",
    "Meta-Generator",
    "Google-Analytics",
    "Google Tag Manager",
    "Google-Tag-Manager",
    "Google Adsense",
    "Google-Adsense",
    "DoubleClick",
    "Facebook",
    "Twitter",
    "YouTube",
    "Font Awesome",
    "jQuery",
    "jQuery Migrate",
    "Bootstrap",
    "Modernizr",
    "Moment.js",
    "Slick",
}
_IGNORED_PLUGINS_LOWER = {p.lower() for p in IGNORED_PLUGINS}

#Whitelist di tecnologie accettate
CORE_PLUGINS_WHITELIST = {

    "apache",
    "nginx",
    "microsoft-iis",
    "litespeed",
    "openresty",
    "caddy",
    "varnish",
    "haproxy",
    "squid",
    "tomcat",
    "jetty",
    "gunicorn",
    "uwsgi",
    "express",
    "node.js",
    "asp.net",
    "php",
    "mod_php",
    "mod_ssl",
    "openssl",
    "python",
    "django",
    "flask",
    "ruby",
    "rails",
    "perl",
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "phpmyadmin",
    "openbsd",
    "openssh",
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


def _is_core_plugin(name):
    """
    Verifica se un plugin di WhatWeb è considerato "core" e quindi rilevante.

    Il controllo viene fatto confrontando il nome del plugin con la whitelist

    Args:
        name (str): Nome del plugin così come riportato da WhatWeb.

    Returns:
        bool: True se il plugin è core, False altrimenti.
    """

    return (name or "").lower() in CORE_PLUGINS_WHITELIST


def _iter_json_values_from_text(text):
    """
    Estrae tutti i valori JSON validi da una stringa, avanzando progressivamente nel buffer.

    Utile per gestire:
      - NDJSON (una riga JSON per linea),
      - array JSON completi o troncati (es. "[{...}, {...} ..." in caso di timeout),
      - output con prefissi/suffissi non JSON (rumore).

    Args:
        text (str): Testo da cui provare ad estrarre oggetti/array JSON.

    Yields:
        Any: Ogni valore JSON decodificato (dict, list, ecc.) trovato nel testo.
    """

    s = _to_str(text or "")
    #Fix per casi in cui stdout è caduto come repr di bytes: "b'...'"
    m = re.match(r"^b(['\"])(.*)\1$", s, re.S)
    if m:
        #interpreta le sequenze \n, \t, ecc.
        s = m.group(2).encode("utf-8", "backslashreplace").decode("unicode_escape")

    dec = json.JSONDecoder()
    i, n = 0, len(s)
    while i < n:
        #salta whitespace/rumore
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            val, j = dec.raw_decode(s, i)
            yield val
            i = j
        except json.JSONDecodeError:
            i += 1


def _add_pair(acc, name, v):
    """
    Aggiunge una coppia (tecnologia, versione) all'insieme, se valida.

    Scarta versioni vuote o placeholder generici ( '?', '-', 'unknown' ).

    Args:
        acc (set): Insieme di coppie (tech, version) in cui inserire il risultato.
        name (str): Nome tecnologia/plugin.
        v (str): Versione associata.
    """

    v = (v or "").strip()
    if not v or v.lower() in {"?", "-", "unknown"}:
        return
    acc.add((name, v))


def extract_versions_from_whatweb(results):
    """
    Estrae una lista unica di coppie (tecnologia, versione) dai risultati di WhatWeb

    Args:
        results (Sequence[WhatWebResult]): Risultati WhatWeb grezzi

    Returns:
        List[Tuple[str, str]]: Lista ordinata e deduplicata di tuple (tecnologia, versione)
    """

    acc: set[Tuple[str, str]] = set()

    for r in results:
        stdout = _to_str(getattr(r, "stdout", "") or "")
        if not stdout:
            continue

        #NDJSON (righe che iniziano con '{')
        had_any = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            _extract_from_plugins_obj(obj.get("plugins"), acc)
            had_any = True

        if had_any:
            continue

        #Fallback: estrai tutti i valori JSON validi dal buffer (array completo o parziale)
        for val in _iter_json_values_from_text(stdout):
            if isinstance(val, dict) and "plugins" in val:
                _extract_from_plugins_obj(val.get("plugins"), acc)
            elif isinstance(val, list):
                for it in val:
                    if isinstance(it, dict) and "plugins" in it:
                        _extract_from_plugins_obj(it.get("plugins"), acc)
            #altri tipi: ignora

    #output ordinato e deduplicato
    return sorted(acc, key=lambda t: (t[0].lower(), t[1]))


def _extract_from_plugins_obj(plugins: Any, acc: set) -> None:
    """
    Estrae informazioni di versione a partire dal campo 'plugins' di WhatWeb.

    Per ogni plugin:
      - se è nella lista da ignorare viene saltato,
      - se è "HTTPServer" si estraggono vendor/version dal banner HTTP,
      - se è un plugin core si usa 'version' se presente, altrimenti
        si prova ad estrarre una versione numerica

    Args:
        plugins (Any): Oggetto associato alla chiave 'plugins' nel JSON di WhatWeb
        acc (set): Insieme delle coppie (tech, version) in cui aggiungere i risultati.
    """

    if not isinstance(plugins, dict):
        return
    for name, info in plugins.items():
        lname = (name or "").lower()
        if lname in _IGNORED_PLUGINS_LOWER:
            continue

        #estrai vendor/version dal banner
        if lname == "httpserver":
            infos: List[dict] = []
            if isinstance(info, dict):
                infos = [info]
            elif isinstance(info, list):
                infos = [x for x in info if isinstance(x, dict)]
            else:
                continue

            for it in infos:
                blob = ""
                s = it.get("string")
                if isinstance(s, list):
                    blob += " ".join(_to_str(x) for x in s)
                elif isinstance(s, str):
                    blob += s
                ss = it.get("strings")
                if isinstance(ss, list):
                    blob += " " + " ".join(_to_str(x) for x in ss)
                elif isinstance(ss, str):
                    blob += " " + ss

                for m in SERVER_TOKEN_RX.finditer(blob):
                    vendor, v = m.group(1), m.group(2)
                    _add_pair(acc, vendor, v)
            continue 

        if not _is_core_plugin(name):
            continue

        #normalizza a lista di dict
        infos: List[dict] = []
        if isinstance(info, dict):
            infos = [info]
        elif isinstance(info, list):
            infos = [x for x in info if isinstance(x, dict)]
        else:
            continue

        for it in infos:
            #'version' esplicita
            ver = it.get("version")
            if isinstance(ver, (str, int, float)):
                _add_pair(acc, name, str(ver))
                continue
            elif isinstance(ver, list):
                any_added = False
                for vv in ver:
                    if isinstance(vv, (str, int, float)):
                        _add_pair(acc, name, str(vv))
                        any_added = True
                if any_added:
                    continue 

            #estrai numeri
            blob = ""
            s = it.get("string")
            if isinstance(s, list):
                blob += " ".join(_to_str(x) for x in s)
            elif isinstance(s, str):
                blob += s
            ss = it.get("strings")
            if isinstance(ss, list):
                blob += " " + " ".join(_to_str(x) for x in ss)
            elif isinstance(ss, str):
                blob += " " + ss

            m = VERSION_RX_WW.search(blob)
            if m:
                _add_pair(acc, name, m.group(0))
