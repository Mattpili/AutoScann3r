from types import SimpleNamespace

#CSS globale
BASE_CSS = """
body{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;margin:22px}
h1{font-size:22px;margin:0 0 14px}
h2{font-size:18px;margin:18px 0 8px}
ul{margin:8px 0 16px;padding-left:20px}
table{border-collapse:collapse;width:100%;margin:8px 0 16px}
th,td{border:1px solid #e7e7e7;padding:6px 8px;vertical-align:top}
th{background:#fafafa;text-align:left}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:12px}
.pill{border:1px solid #ddd;padding:2px 6px;border-radius:6px;background:#f7f7f7;margin-right:4px;white-space:nowrap}
.url{word-break:break-all}
.muted{color:#666}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
.ww details{border:1px solid #e7e7e7;border-radius:8px;margin:8px 0;background:#fafafa}
.ww summary{cursor:pointer;padding:8px 10px;font-weight:600}
.ww .body{padding:8px 10px;background:#fff;border-top:1px solid #e7e7e7}
.ww .row{margin:6px 0}
.ww .label{display:inline-block;min-width:90px;color:#555}
.ww pre{white-space:pre-wrap;word-break:break-word;margin:8px 0;font:12px/1.4 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
.ww .stderr{background:#fff7f7;border-left:4px solid #d0471b;padding-left:8px}
.ok{color:#2b7b2b}
.fail{color:#d0471b}
.risk-legend{margin-top:6px;color:#555}
"""

#Frammenti HTML riutilizzabili
TPL_HEAD = "<head><meta charset='utf-8'><title>{title}</title><style>{css}</style></head>"
TPL_HTML_START = "<html>{head}<body>"
TPL_HTML_END = "</body></html>"
TPL_H1 = "<h1>{text}</h1>"
TPL_H2 = "<h2>{text}</h2>"

#Sezione "Porte aperte e servizi"
TPL_OPEN_PORTS_EMPTY = "<p class='muted'>Nessuna porta aperta rilevata.</p>"
TPL_OPEN_PORTS_TABLE_OPEN = (
    "<table><thead><tr>"
    "<th>Porta</th><th>Proto</th><th>Servizio</th><th>Prodotto/Versione</th>"
    "<th>Rischio</th><th>Motivo</th>"
    "</tr></thead><tbody>"
)
TPL_OPEN_PORTS_ROW = (
    "<tr>"
    "<td><b>{port}</b></td>"
    "<td>{proto}</td>"
    "<td><code>{service}</code></td>"
    "<td>{prodver}</td>"
    "<td>{risk_badge}</td>"
    "<td>{reason}</td>"
    "</tr>"
)
TPL_OPEN_PORTS_TABLE_CLOSE = "</tbody></table>"
TPL_RISK_LEGEND = (
    "<div class='risk-legend'>Legenda: "
    "🟢 atteso • 🟡 da valutare • 🔴 rischioso • ⚪ sconosciuto </div>"
)

#Sezione CVE
TPL_CVE_EMPTY = "<p class='muted'>Nessun exploit/CVE trovato.</p>"
TPL_CVE_TABLE_OPEN = (
    "<table><thead><tr>"
    "<th>EDB-ID</th><th>Titolo</th><th>CVEs</th><th>Max CVSS</th><th>Severity</th>"
    "</tr></thead><tbody>"
)
TPL_CVE_ROW = (
    "<tr>"
    "<td><a class='url' href='{edb_url}' target='_blank' rel='noopener'>{edb}</a></td>"
    "<td>{title}</td>"
    "<td>{cves_html}</td>"
    "<td>{max_cvss}</td>"
    "<td>{sev_badge}</td>"
    "</tr>"
)
TPL_CVE_TABLE_CLOSE = "</tbody></table>"

#Sezione WhatWeb
TPL_WW_WRAP_OPEN = "<div class='ww'><h2>{title}</h2>"
TPL_WW_WRAP_EMPTY = "<p class='mono'>Nessun risultato disponibile.</p></div>"
TPL_WW_DETAILS_OPEN = "<details>"
TPL_WW_SUMMARY = (
    "{sym} <span class='{status}'>{target}</span> "
    "<span class='mono' style='color:#777'>(exit {code})</span>"
)
TPL_WW_SUMMARY_WRAP = "<summary>{inner}</summary>"
TPL_WW_BODY_OPEN = "<div class='body'>"
TPL_WW_ROW_CMD = "<div class='row'><span class='label'>Comando</span><span class='mono'>{cmd}</span></div>"
TPL_WW_ROW_STDOUT = "<div class='row'><div class='label'>STDOUT</div><pre>{stdout}</pre></div>"
TPL_WW_ROW_STDERR = "<div class='row'><div class='label'>STDERR</div><pre class='stderr'>{stderr}</pre></div>"
TPL_WW_BODY_CLOSE = "</div>"
TPL_WW_DETAILS_CLOSE = "</details>"
TPL_WW_WRAP_CLOSE = "</div>"
TPL_WW_TECH_EMPTY = "<p class='muted'>Nessuna tecnologia identificata.</p>"
TPL_WW_TECH_WRAP_OPEN = "<ul>"
TPL_WW_TECH_ITEM = "<li>{tech} — <b>{ver}</b></li>"
TPL_WW_TECH_WRAP_CLOSE = "</ul>"

T = SimpleNamespace(
    BASE_CSS=BASE_CSS,
    TPL_HEAD=TPL_HEAD,
    TPL_HTML_START=TPL_HTML_START,
    TPL_HTML_END=TPL_HTML_END,
    TPL_H1=TPL_H1, TPL_H2=TPL_H2,
    TPL_OPEN_PORTS_EMPTY=TPL_OPEN_PORTS_EMPTY,
    TPL_OPEN_PORTS_TABLE_OPEN=TPL_OPEN_PORTS_TABLE_OPEN,
    TPL_OPEN_PORTS_ROW=TPL_OPEN_PORTS_ROW,
    TPL_OPEN_PORTS_TABLE_CLOSE=TPL_OPEN_PORTS_TABLE_CLOSE,
    TPL_RISK_LEGEND=TPL_RISK_LEGEND,
    TPL_CVE_EMPTY=TPL_CVE_EMPTY,
    TPL_CVE_TABLE_OPEN=TPL_CVE_TABLE_OPEN,
    TPL_CVE_ROW=TPL_CVE_ROW,
    TPL_CVE_TABLE_CLOSE=TPL_CVE_TABLE_CLOSE,
    TPL_WW_WRAP_OPEN=TPL_WW_WRAP_OPEN,
    TPL_WW_WRAP_EMPTY=TPL_WW_WRAP_EMPTY,
    TPL_WW_DETAILS_OPEN=TPL_WW_DETAILS_OPEN,
    TPL_WW_SUMMARY=TPL_WW_SUMMARY,
    TPL_WW_SUMMARY_WRAP=TPL_WW_SUMMARY_WRAP,
    TPL_WW_BODY_OPEN=TPL_WW_BODY_OPEN,
    TPL_WW_ROW_CMD=TPL_WW_ROW_CMD,
    TPL_WW_ROW_STDOUT=TPL_WW_ROW_STDOUT,
    TPL_WW_ROW_STDERR=TPL_WW_ROW_STDERR,
    TPL_WW_BODY_CLOSE=TPL_WW_BODY_CLOSE,
    TPL_WW_DETAILS_CLOSE=TPL_WW_DETAILS_CLOSE,
    TPL_WW_WRAP_CLOSE=TPL_WW_WRAP_CLOSE,
    TPL_WW_TECH_EMPTY=TPL_WW_TECH_EMPTY,
    TPL_WW_TECH_WRAP_OPEN=TPL_WW_TECH_WRAP_OPEN,
    TPL_WW_TECH_ITEM=TPL_WW_TECH_ITEM,
    TPL_WW_TECH_WRAP_CLOSE=TPL_WW_TECH_WRAP_CLOSE,
)

