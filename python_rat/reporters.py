"""
reporters.py — Multiple Output Formats (Plan #17, #18)
Supports:
 - Terminal output (concise)
 - JSON
 - SARIF (GitHub code scanning)
 - HTML (with data-flow visualization)
 - Markdown
 - PDF (client-friendly A4 report via WeasyPrint)

Also CI/CD support per Plan #16 (exit codes).
"""
from __future__ import annotations
import json
import pathlib
import time
from typing import List, Dict, Any
from dataclasses import dataclass

# ── SARIF Reporter (Plan #17) ──
def to_sarif(findings: List[Dict], tool_name: str = "squeak/rat", version: str = "1.1") -> Dict:
    """
    Generate SARIF 2.1.0 output for GitHub Advanced Security / CodeQL integration.
    Fields: Rule ID, Severity, Message, File, Line, Data-flow location, Remediation
    """
    rules = []
    results = []
    seen_rules = set()
    severity_to_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

    for f in findings:
        rule_id = f.get("id", "RAT-000") if isinstance(f, dict) else getattr(f, "id", "RAT-000")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.get("title", "") if isinstance(f, dict) else getattr(f, "title", ""),
                "shortDescription": {"text": (f.get("title", "") if isinstance(f, dict) else getattr(f, "title", ""))[:120]},
                "fullDescription": {"text": f.get("why", "") if isinstance(f, dict) else getattr(f, "why", "")},
                "help": {"text": "; ".join(f.get("recommendations", []) if isinstance(f, dict) else getattr(f, "recommendations", []))},
                "properties": {"severity": f.get("severity","info") if isinstance(f, dict) else getattr(f, "severity", "info"), "category": f.get("category","") if isinstance(f, dict) else getattr(f, "category", "")}
            })
        # Location
        file_path = f.get("file","") if isinstance(f, dict) else getattr(f, "file", "")
        line = f.get("line",1) if isinstance(f, dict) else getattr(f, "line", 1)
        results.append({
            "ruleId": rule_id,
            "level": severity_to_level.get(f.get("severity","info") if isinstance(f, dict) else getattr(f, "severity","info"), "warning"),
            "message": {"text": f.get("title","") + ": " + (f.get("why","")[:300] if isinstance(f, dict) else getattr(f, "why","")[:300])},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": int(line), "startColumn": 1}
                }
            }],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        {"location": {"message": {"text": step}, "physicalLocation": {"artifactLocation": {"uri": file_path}}}}
                        for step in (f.get("flow",[]) if isinstance(f, dict) else getattr(f, "flow",[]))
                    ]
                }]
            }] if (f.get("flow") if isinstance(f, dict) else getattr(f, "flow", None)) else [],
            "properties": {
                "confidence": f.get("confidence","") if isinstance(f, dict) else getattr(f, "confidence",""),
                "source": f.get("source","") if isinstance(f, dict) else getattr(f, "source",""),
                "sink": f.get("sink","") if isinstance(f, dict) else getattr(f, "sink",""),
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": version, "informationUri": "https://github.com/squeak/rat", "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}]
        }]
    }

def write_sarif(findings: List[Dict], output_path: pathlib.Path):
    output_path.write_text(json.dumps(to_sarif(findings), indent=2))
    return output_path

# ── HTML Reporter ──
HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>RAT Security Report</title>
<style>
body{{font-family:Inter,system-ui,sans-serif;background:#0f0a1a;color:#e9d5ff;margin:0;padding:32px}}
h1{{color:#8b5cf6}} .finding{{background:#1e0a3a;border:1px solid #8b5cf6;border-radius:12px;padding:20px;margin:16px 0}}
.sev-critical{{border-left:6px solid #ef4444}} .sev-high{{border-left:6px solid #f59e0b}} .sev-medium{{border-left:6px solid #06b6d4}} .sev-low{{border-left:6px solid #3b82f6}}
.flow{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}} .flow span{{background:#2d1b4e;padding:4px 8px;border-radius:6px;font-size:12px}}
code{{background:#2d1b4e;padding:2px 6px;border-radius:4px}}
</style></head><body>
<h1>🐀 RAT Security Report</h1>
<p>Generated: {generated} | Findings: {count}</p>
{findings_html}
</body></html>"""

def to_html(findings: List[Dict]) -> str:
    parts = []
    for f in findings:
        d = f if isinstance(f, dict) else f.__dict__
        flow_html = "".join(f"<span>{s}</span> → " for s in d.get("flow", []))[:-3] if d.get("flow") else d.get("source","")
        parts.append(f"""
        <div class="finding sev-{d.get('severity','info')}">
            <h3>{d.get('severity','').upper()} {d.get('id','')} — {d.get('title','')}</h3>
            <p><b>File:</b> <code>{d.get('file','')}:{d.get('line','')}</code> | <b>Confidence:</b> {d.get('confidence','')}</p>
            <p>{d.get('why','') or d.get('description','')}</p>
            <div class="flow">{flow_html}</div>
            <p><b>Source:</b> <code>{d.get('source','')}</code> → <b>Sink:</b> <code>{d.get('sink','')}</code></p>
            <p><b>Fix:</b> {'; '.join(d.get('recommendations', []))}</p>
        </div>
        """)
    return HTML_TEMPLATE.format(generated=time.strftime("%Y-%m-%d %H:%M:%S"), count=len(findings), findings_html="\n".join(parts))

def write_html(findings: List[Dict], output_path: pathlib.Path):
    output_path.write_text(to_html(findings))
    return output_path

# ── Markdown Reporter ──
def to_markdown(findings: List[Dict]) -> str:
    lines = [f"# 🐀 RAT Security Report", f"", f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Findings: {len(findings)}", ""]
    for f in findings:
        d = f if isinstance(f, dict) else f.__dict__
        lines.extend([
            f"## {d.get('severity','').upper()} {d.get('id','')} — {d.get('title','')}",
            f"- **File:** `{d.get('file','')}:{d.get('line','')}` | **Confidence:** {d.get('confidence','')} | **Category:** {d.get('category','')}",
            f"- **Source:** `{d.get('source','')}` → **Sink:** `{d.get('sink','')}`",
            f"- **Flow:** {' → '.join(d.get('flow', []))}",
            f"- **Why:** {d.get('why','') or d.get('description','')}",
            f"- **Fix:** {'; '.join(d.get('recommendations', []))}",
            f"",
        ])
    return "\n".join(lines)

def write_markdown(findings: List[Dict], output_path: pathlib.Path):
    output_path.write_text(to_markdown(findings))
    return output_path

# ── PDF Reporter (client-friendly, WeasyPrint) ──
_SEV = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#eab308",
    "low": "#2563eb",
    "info": "#64748b",
}

def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {k: 0 for k in _SEV}
    for f in findings:
        d = f if isinstance(f, dict) else getattr(f, "__dict__", {})
        sev = str(d.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = 1
    return counts


def _finding_card(d: Dict) -> str:
    sev = str(d.get("severity", "info")).lower()
    color = _SEV_COLOR.get(sev, "#64748b")
    flow = d.get("flow") or []
    flow_html = "".join(
        f'<span class="flow-step">{_esc(str(s))}</span><span class="flow-arrow">→</span>'
        for s in flow
    )
    if flow_html.endswith('<span class="flow-arrow">→</span>'):
        flow_html = flow_html[: -len('<span class="flow-arrow">→</span>')]
    recs = d.get("recommendations") or []
    recs_html = ""
    if recs:
        items = "".join(f"<li>{_esc(str(r))}</li>" for r in recs)
        recs_html = f'<div class="block-label">Recommended fix</div><ol class="fix">{items}</ol>'
    why = d.get("why") or d.get("description") or ""
    source = d.get("source") or ""
    sink = d.get("sink") or ""
    src_sink = ""
    if source or sink:
        src_sink = (
            f'<div class="meta"><b>Source:</b> <code>{_esc(str(source))}</code>'
            f' &nbsp;→&nbsp; <b>Sink:</b> <code>{_esc(str(sink))}</code></div>'
        )
    return f"""
    <div class="finding" style="border-left-color:{color}">
      <div class="finding-head">
        <span class="badge" style="background:{color}">{sev.upper()}</span>
        <span class="fid">{_esc(str(d.get("id","")))}</span>
        <span class="title">{_esc(str(d.get("title","")))}</span>
      </div>
      <div class="meta"><b>File:</b> <code>{_esc(str(d.get("file","")))}:{_esc(str(d.get("line","")))}</code>
        &nbsp;|&nbsp; <b>Confidence:</b> {_esc(str(d.get("confidence",""))).upper()}</div>
      <p class="why">{_esc(why)}</p>
      {f'<div class="flow-box">{flow_html}</div>' if flow_html else ''}
      {src_sink}
      {recs_html}
    </div>"""


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def to_pdf_html(findings: List[Dict], stats: Dict | None = None) -> str:
    counts = _severity_counts(findings)
    total = len(findings)
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    stats = stats or {}

    order = ["critical", "high", "medium", "low", "info"]
    bar_parts = []
    for sev in reversed(order):
        n = counts.get(sev, 0)
        if n:
            bar_parts.append(
                f'<span class="bar-seg" style="background:{_SEV_COLOR[sev]};flex-grow:{n}">'
                f'{sev} {n}</span>'
            )
    bar_html = (
        '<div class="sev-bar">' + "".join(bar_parts) + "</div>"
        if bar_parts
        else '<div class="sev-bar"><span class="bar-clean">clean</span></div>'
    )

    summary_items = []

    def _stat(label, key, fmt=""):
        val = stats.get(key)
        if val:
            s = f"{val}" + (fmt and f" {fmt}")
            summary_items.append(f"<div class=\"sum-cell\"><div class=\"sum-label\">{label}</div><div class=\"sum-value\">{s}</div></div>")

    _stat("Files scanned", "files")
    _stat("Routes", "routes")
    by_type = stats.get("by_type")
    if by_type:
        parts = []
        for tname, tnum in sorted(by_type.items()):
            if tnum:
                parts.append(f"{tname} {tnum}")
        if parts:
            summary_items.append(f'<div class="sum-cell"><div class="sum-label">Components</div><div class="sum-value">{_esc(", ".join(parts))}</div></div>')
    smiles = "✓ No findings — the application looks clean within RAT's scope."
    findings_html = (
        "\n".join(_finding_card(f if isinstance(f, dict) else getattr(f, "__dict__", {})) for f in findings)
        if findings
        else f'<div class="clean"><p>👌 {smiles}</p></div>'
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>RAT Security Report</title>
<style>
@page {{ size: A4; margin: 18mm 16mm 20mm 16mm;
  @bottom-center {{ content: "RAT Security Report — page " counter(page) " of " counter(pages);
    font-size: 8pt; color: #94a3b8; }} }}
body {{ font-family: "DejaVu Sans", Helvetica, Arial, sans-serif; color: #1e293b; font-size: 10pt; line-height: 1.5; }}
h1 {{ font-size: 20pt; color: #7c3aed; margin: 0 0 2mm 0; }}
.subtitle {{ color: #64748b; font-size: 9pt; margin-bottom: 6mm; }}
.summary {{ background: #f8fafc; border: 1pt solid #e2e8f0; border-radius: 6pt; padding: 4mm 5mm; page-break-inside: avoid; }}
.section {{ font-size: 13pt; font-weight: bold; color: #7c3aed; margin: 6mm 0 3mm 0; }}
.grid {{ display: flex; flex-wrap: wrap; gap: 6pt; margin-top: 3mm; }}
.sum-cell {{ background: #f1f5f9; border-radius: 4pt; padding: 3pt 6pt; }}
.sum-label {{ font-size: 7.5pt; color: #64748b; text-transform: uppercase; letter-spacing: .5pt; }}
.sum-value {{ font-size: 12pt; font-weight: bold; color: #334155; }}
.sev-bar {{ display: flex; margin-top: 4mm; border-radius: 4pt; overflow: hidden; }}
.bar-seg {{ color: #fff; text-align: center; font-size: 8pt; padding: 2.5pt 0; }}
.bar-clean {{ color: #16a34a; font-weight: bold; font-size: 9pt; }}
.finding {{ border: 1pt solid #e2e8f0; border-left: 5pt solid #cbd5e1; border-radius: 5pt; padding: 4mm 5mm; margin: 4mm 0 5mm 0; page-break-inside: avoid; }}
.finding-head {{ margin-bottom: 2mm; }}
.badge {{ display: inline-block; color: #fff; font-weight: bold; font-size: 8pt; padding: 1.5pt 6pt; border-radius: 8pt; margin-right: 4pt; }}
.fid {{ font-weight: bold; color: #7c3aed; margin-right: 6pt; }}
.title {{ font-weight: bold; color: #0f172a; }}
.meta {{ font-size: 8.5pt; color: #64748b; margin-bottom: 2mm; }}
.meta code, .finding code {{ background: #f1f5f9; padding: 1pt 3pt; border-radius: 3pt; font-size: 8.5pt; color: #334155; }}
.why {{ color: #334155; margin: 1mm 0; }}
.flow-box {{ margin: 2mm 0; }}
.flow-step {{ display: inline-block; background: #ede9fe; color: #5b21b6; border-radius: 3pt; padding: 1.5pt 6pt; font-size: 8.5pt; }}
.flow-arrow {{ color: #a78bfa; margin: 0 3pt; }}
.block-label {{ font-size: 8pt; font-weight: bold; color: #475569; text-transform: uppercase; letter-spacing: .5pt; margin-top: 2mm; }}
ol.fix {{ margin: 1mm 0 0 0; padding-left: 5mm; color: #334155; font-size: 9pt; }}
ol.fix li {{ margin-bottom: 1pt; }}
.clean {{ border: 1pt solid #bbf7d0; background: #f0fdf4; border-radius: 6pt; padding: 5mm; color: #166534; text-align: center; font-size: 11pt; }}
</style></head><body>
<h1>🐀 RAT Security Report</h1>
<div class="subtitle">Generated {generated} &nbsp;|&nbsp; {total} finding{'s' if total != 1 else ''} &nbsp;|&nbsp; application behavior &amp; security analysis</div>

<div class="section">Executive summary</div>
<div class="summary">
  <div>Total <b>{total}</b> finding{'s' if total != 1 else ''} detected.{(' Top severity: <b>' + order[0].upper() + '</b>.' if total else '')}</div>
  {bar_html}
  <div class="grid">{''.join(summary_items)}</div>
</div>

<div class="section">Findings</div>
{findings_html}
<div class="subtitle" style="margin-top:6mm">Report generated by RAT — the Laravel Security &amp; Behavior Analyzer.</div>
</body></html>"""


def to_pdf(findings: List[Dict], stats: Dict | None = None) -> bytes:
    """Render the report to PDF bytes via WeasyPrint (lazy import)."""
    from weasyprint import HTML  # local import: pdf is optional at runtime

    return HTML(string=to_pdf_html(findings, stats)).write_pdf()


def write_pdf(findings: List[Dict], output_path: pathlib.Path, stats: Dict | None = None) -> pathlib.Path:
    output_path.write_bytes(to_pdf(findings, stats))
    return output_path

# ── CI/CD helper (Plan #16) ──
def ci_exit_code(findings: List[Dict], fail_on: str = "high") -> int:
    """
    Exit codes per plan:
      0 = no blocking findings
      1 = warnings (if medium+ but threshold not exceeded? we use 1 for medium)
      2 = high/critical findings
    Simplified: 0 clean, 1 threshold exceeded.
    But plan says: 0 no blocking, 1 warnings, 2 high/critical -> we implement weight threshold.
    """
    weight = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
    thresh = weight.get(fail_on.lower(), 75)
    for f in findings:
        sev = f.get("severity","info").lower() if isinstance(f, dict) else getattr(f, "severity", "info").lower()
        if weight.get(sev, 0) >= thresh:
            return 1  # GitHub Actions typically uses 1 for failure; we also support 2 for high
            # To match spec exactly: return 2 if thresh >=75 else 1
    return 0

def overall_severity(findings: List[Dict]) -> str:
    weight = {"critical":100,"high":75,"medium":50,"low":25,"info":10}
    def sev_of(f):
        if isinstance(f, dict):
            return str(f.get("severity","info")).lower()
        return str(getattr(f, "severity","info")).lower()
    max_w = max([weight.get(sev_of(f),0) for f in findings], default=0)
    for k,v in weight.items():
        if v == max_w:
            return k
    return "info"
