#!/usr/bin/env python3
"""
rat.py — Python-native RAT CLI
Mirrors PHP RatCommand.php / bin/rat default command but uses Python analyzer (precise, no false positives).

Usage (Laravel package — php artisan delegates to Python precise):
  php artisan rat                         # interactive chooser (TTY) → Python engine
  php artisan rat --all                   # [all] Whole codebase (all PHP — recommended, respects exclude)
  php artisan rat --laravel               # [laravel] Laravel lot
  php artisan rat --security              # [security] Security scan
  php artisan rat --deep                  # [deep] Deep security scan
  php artisan rat --path=app,routes       # [custom] Custom
  php artisan rat --all --format=json > report.json
  php artisan rat --deep --ci --fail-on=high
  php artisan rat:show RAT-001            # investigate finding (reads last.json)
  php artisan rat:show --format=json
  php artisan rat:flow "POST /api/import"
  php artisan rat:why UserController
  # standalone Python (same engine):
  python3 rat.py --all  |  python3 vendor/squeak/rat/rat.py --deep

Scope logic exactly mirrors PHP:
  --deep > --security > --all > --laravel > --path > interactive > config/rat.php default
  respects exclude (vendor/storage/bootstrap/cache/node_modules/public/.git)
"""

import argparse
import json
import sys
import pathlib
import time

ROOT = pathlib.Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

from python_rat.banner import render_banner
from python_rat.config import load_config, resolve_scope
from python_rat.analyzer import Analyzer

def persist_last_scan(findings, stats, graph):
    payload={
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "stats": stats,
        "findings": findings,
        "graph": graph.to_dict(),
    }
    d1=pathlib.Path.cwd()/ "storage/rat"
    d1.mkdir(parents=True, exist_ok=True)
    (d1/"last.json").write_text(json.dumps(payload, indent=2))
    (pathlib.Path.cwd()/".rat.last.json").write_text(json.dumps(payload, indent=2))
    # also .rat/last.json equivalent
    d2=pathlib.Path.cwd()/".rat"
    if d2.is_dir() or True:
        try:
            d2.mkdir(exist_ok=True)
            (d2/"last.json").write_text(json.dumps(payload, indent=2))
        except: pass

def render_stats(stats):
    # violet progress bar simulation
    print("  \033[38;2;139;92;246mAnalyzing application behavior...\033[0m\n")
    # progress
    bar_len=22
    for pct in range(0,101,25):
        filled=int(bar_len*pct/100)
        bar="\033[38;2;139;92;246m"+"█"*filled+"\033[90m"+"░"*(bar_len-filled)+"\033[0m"
        sys.stdout.write(f"\r  {bar}  \033[38;2;167;139;250m{pct:3d}%\033[0m")
        sys.stdout.flush()
        time.sleep(0.035)
    print("\n")
    by_type=stats.get("by_type",{})
    g_by=stats.get("graph",{}).get("by_type",{})
    routes=stats.get("routes",0)
    controllers=by_type.get("Controller", g_by.get("Controller",0))
    models=by_type.get("Model", g_by.get("Model",0))
    services=by_type.get("Service", g_by.get("Service",0))
    jobs=by_type.get("Job", g_by.get("Job",0))
    def pad(label,count):
        dots="."*max(1, 22-len(label))
        return f"  \033[90m{label}\033[0m {dots} {count}"
    print(pad("Routes", routes))
    print(pad("Controllers", controllers))
    print(pad("Models", models))
    print(pad("Services", services))
    print(pad("Jobs", jobs))
    print(pad("Events", by_type.get("Event", g_by.get("Event",0))))
    print()

def render_findings_summary(findings):
    counts={"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f.get("severity","info")]+=1
    print("  \033[97;1mFindings\033[0m")
    print("  \033[90m──────────────────────────────────────────────\033[0m")
    def lbl(sev,color,count):
        return f"  \033[38;2;{color}m{sev:8}\033[0m \033[97m{count}\033[0m"
    # use ansi mapped: critical red, high yellow etc but keep violet for low
    print(f"  \033[91;1m{'CRITICAL':8}\033[0m \033[97m{counts['critical']}\033[0m")
    print(f"  \033[93;1m{'HIGH':8}\033[0m \033[97m{counts['high']}\033[0m")
    print(f"  \033[96;1m{'MEDIUM':8}\033[0m \033[97m{counts['medium']}\033[0m")
    print(f"  \033[94;1m{'LOW':8}\033[0m \033[97m{counts['low']}\033[0m")
    if counts['info']>0:
        print(f"  \033[90;1m{'INFO':8}\033[0m \033[97m{counts['info']}\033[0m")
    print()
    if findings:
        print("  \033[90mRun:\033[0m")
        print("    \033[96mphp artisan rat:show\033[0m           \033[90m— list all findings\033[0m")
        print("    \033[96mphp artisan rat:show RAT-001\033[0m   \033[90m— investigate one\033[0m")
        print("    \033[96mphp artisan rat:flow \"POST /api/import\"\033[0m \033[90m— trace a route\033[0m")
    else:
        print("  \033[92m✓ No findings — application looks clean (within RAT’s scope).\033[0m")
        print("  \033[90m  Tip: `php artisan rat:why <Controller>` and `php artisan rat:impact <Model>` for exploration.\033[0m")
    print()

def handle_scan(args):
    project_root=pathlib.Path.cwd()
    cfg=load_config(project_root)
    cfg=resolve_scope(project_root, cfg, args)
    # Handle exclude override
    if getattr(args, "exclude", None):
        cfg["exclude"] = [e.strip() for e in args.exclude.split(",") if e.strip()]
    # Handle flush cache (incremental)
    if getattr(args, "flush_cache", False):
        try:
            from python_rat.cache_manager import get_cache_manager
            from python_rat.ast_parser import PhpAstParser
            get_cache_manager(project_root).flush()
            PhpAstParser(project_root).flush_cache()
            print("  \033[90mCache flushed.\033[0m")
        except Exception as e:
            print(f"  \033[91mCache flush failed: {e}\033[0m")

    is_json=args.format in ("json","ndjson") or bool(getattr(args,"json",False))
    # New formats per Plan #17, #18: sarif, html, markdown are also machine-readable
    is_machine = args.format in ("json","ndjson","sarif","html","markdown") or bool(getattr(args,"json",False))
    no_image=bool(getattr(args,"no_image",False))
    compact=bool(getattr(args,"compact",False))
    ci=bool(getattr(args,"ci",False))

    if not is_machine:
        render_banner(with_image=not no_image, compact=compact)
        if getattr(args,"deep",False):
            print("  \033[38;2;139;92;246;1m🐀 RAT // DEEP SECURITY SCAN\033[0m")
            print("  \033[38;2;167;139;250mAdvanced data-flow + behavior analysis — whole codebase, vendor excluded\033[0m")
        elif getattr(args,"security",False):
            print("  \033[38;2;139;92;246;1m🐀 RAT // SECURITY SCAN\033[0m")
            print("  \033[90mVulnerability & attack-surface — whole codebase, vendor excluded\033[0m")
        print()
        print("  \033[38;2;139;92;246mScanning application...\033[0m")
        print()

    analyzer=Analyzer(project_root, cfg)
    result=analyzer.analyze()
    findings=result["findings"]
    stats=result["stats"]
    graph=result["graph"]

    if not is_machine:
        render_stats(stats)
        render_findings_summary(findings)
        # Performance stats (Plan #15 incremental)
        perf = stats.get("performance", {})
        if perf:
            print(f"  \033[90mPerformance: {perf.get('total_ms',0):.0f}ms | files {perf.get('files_ms',0):.0f}ms | flows {perf.get('flows_ms',0):.0f}ms | incremental hit {perf.get('incremental_hit_rate',0):.0%} | cache {stats.get('incremental',{}).get('cached_files',0)} files\033[0m")
        print("  \033[90mFlags: --format=json | --format=sarif | --format=html | --format=markdown | --ci | --fail-on=high | --flush-cache\033[0m")
        print("  \033[90mScope: by default whole codebase (excl. vendor/storage/public/.git) — use --all or choose interactively\033[0m")
        print("  \033[90mUpdate: composer update squeak/rat --with-all-dependencies\033[0m")
        print()

    # machine-readable per Plan #17, #18
    if args.format=="json" or getattr(args,"json",False):
        print(json.dumps({"findings": findings, "stats": stats}, indent=2))
    elif args.format=="ndjson":
        for f in findings:
            print(json.dumps(f))
    elif args.format=="sarif":
        try:
            from python_rat.reporters import to_sarif
            print(json.dumps(to_sarif(findings), indent=2))
        except Exception as e:
            print(json.dumps({"error": str(e), "findings": findings}, indent=2))
    elif args.format=="html":
        try:
            from python_rat.reporters import to_html
            print(to_html(findings))
        except Exception as e:
            print(f"HTML error: {e}")
            print(json.dumps({"findings": findings}, indent=2))
    elif args.format=="markdown":
        try:
            from python_rat.reporters import to_markdown
            print(to_markdown(findings))
        except Exception as e:
            print(f"Markdown error: {e}")
            print(json.dumps({"findings": findings}, indent=2))

    if ci:
        fail_on=getattr(args,"fail_on",None) or cfg.get("fail_on","high")
        if "/" in str(fail_on): fail_on=cfg.get("fail_on","high")
        weight={"critical":100,"high":75,"medium":50,"low":25,"info":10}
        thresh=weight.get(str(fail_on).lower(),75)
        counts={k:0 for k in weight}
        for f in findings: counts[f.get("severity","info")]+=1
        print()
        print("  \033[97;1mRAT CI CHECK\033[0m")
        print("  \033[90m──────────────────────────────\033[0m")
        print(f"  Critical: \033[91m{counts['critical']}\033[0m")
        print(f"  High:     \033[93m{counts['high']}\033[0m")
        print(f"  Medium:   \033[96m{counts['medium']}\033[0m")
        print()
        # baseline
        baseline_path=pathlib.Path(cfg.get("baseline", str(project_root/".rat.baseline.json")))
        if not baseline_path.is_absolute(): baseline_path=project_root/baseline_path
        baseline=None
        if baseline_path.exists():
            try: baseline=json.loads(baseline_path.read_text())
            except: pass
        new_findings=findings
        if isinstance(baseline,dict) and "findings" in baseline:
            hashes={ (bf.get("title","")+bf.get("file","")+bf.get("sink","")).__hash__():True for bf in baseline["findings"] } # simplified; use md5 string
            # better md5
            import hashlib
            hashes=set()
            for bf in baseline["findings"]:
                h=hashlib.md5((bf.get("title","")+bf.get("file","")+bf.get("sink","")).encode()).hexdigest()
                hashes.add(h)
            filtered=[]
            for f in findings:
                h=hashlib.md5((f.get("title","")+f.get("file","")+f.get("sink","")).encode()).hexdigest()
                if h not in hashes: filtered.append(f)
            new_findings=filtered
        violations=[f for f in new_findings if weight.get(f.get("severity","info"),0) >= thresh]
        if violations:
            print("  \033[91;1m✗ Security threshold exceeded.\033[0m")
            print(f"  \033[90mThreshold: {str(fail_on).upper()} | Violations: {len(violations)}{' (new vs baseline)' if baseline else ''}\033[0m")
            print("  \033[90mExit code: 1\033[0m")
            persist_last_scan(findings, stats, graph)
            return 1
        print("  \033[92;1m✓ CI check passed.\033[0m")
        print("  \033[90mExit code: 0\033[0m")
        persist_last_scan(findings, stats, graph)
        return 0

    persist_last_scan(findings, stats, graph)
    return 0

# ---------------- show / flow / why / impact helpers (python reads last.json same as php)

def load_last():
    for p in [pathlib.Path.cwd()/"storage/rat/last.json", pathlib.Path.cwd()/".rat.last.json", pathlib.Path.cwd()/".rat/last.json"]:
        if p.exists():
            try:
                d=json.loads(p.read_text())
                if "findings" in d: return d
            except: pass
    return None

def cmd_show(args):
    data=load_last()
    if not data:
        print(" \033[93mNo previous scan — running quick analysis...\033[0m")
        cfg=load_config(pathlib.Path.cwd())
        res=Analyzer(pathlib.Path.cwd(), cfg).analyze()
        data={"findings": res["findings"], "stats": res["stats"], "graph": res["graph"].to_dict()}
    findings=data.get("findings",[])
    stats=data.get("stats",{})
    fmt=getattr(args,"format","table")
    target=getattr(args,"id",None)
    if fmt=="json":
        if target:
            needle=str(target).upper()
            found=next((f for f in findings if f.get("id","").upper()==needle), None)
            print(json.dumps(found if found else {"error":"not found","id":target}, indent=2))
            return 0 if found else 1
        print(json.dumps({"findings":findings,"stats":stats}, indent=2))
        return 0
    # table
    if not target:
        if not getattr(args,"no_image",False):
            render_banner(with_image=True, compact=False)
        counts={"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in findings: counts[f.get("severity","info")]+=1
        print(f"\n  \033[90mAll findings:\033[0m \033[97m{len(findings)}\033[0m  \033[90m|\033[0m \033[91mCRITICAL {counts['critical']}\033[0m \033[93mHIGH {counts['high']}\033[0m \033[96mMEDIUM {counts['medium']}\033[0m \033[94mLOW {counts['low']}\033[0m")
        print("  \033[90m"+ "─"*72 +"\033[0m\n")
        if not findings:
            print("  \033[92m✓ No findings.\033[0m"); return 0
        for f in findings:
            sev=f.get("severity","info").upper()
            col={"CRITICAL":"91","HIGH":"93","MEDIUM":"96","LOW":"94"}.get(sev,"90")
            print(f"  \033[{col};1m{sev:8}\033[0m \033[97;1m{f.get('id','?')}\033[0m")
            print(f"  \033[97m{f.get('title','')}\033[0m")
            if f.get("entry"): print(f"  \033[90m{f.get('entry')}\033[0m")
            if f.get("file"): print(f"  \033[90m{f.get('file')}:{f.get('line','')}\033[0m  \033[90mConfidence:\033[0m \033[97m{f.get('confidence','').upper()}\033[0m")
            print(f"  \033[90m→\033[0m \033[96mphp artisan rat:show {f.get('id')}\033[0m\n")
        return 0
    low=str(target).lower()
    if low in ["critical","high","medium","low","info"]:
        filt=[f for f in findings if f.get("severity","")==low]
        render_banner(with_image=True, compact=False)
        print(f"\n  \033[90mFilter:\033[0m \033[97;1m{low.upper()}\033[0m  \033[90m({len(filt)} findings)\033[0m")
        print("  \033[90m"+"─"*72+"\033[0m\n")
        if not filt: print("  \033[92m✓ No findings for this filter.\033[0m"); return 0
        for f in filt:
            sev=f.get("severity","").upper()
            col={"CRITICAL":"91","HIGH":"93","MEDIUM":"96","LOW":"94"}.get(sev,"90")
            print(f"  \033[{col};1m{sev:8}\033[0m \033[97;1m{f.get('id')}\033[0m")
            print(f"  \033[97m{f.get('title')}\033[0m\n")
        return 0
    # single
    norm=str(target).upper().strip()
    import re as _re
    m=_re.match(r'^R0*(\d+)$', norm)
    if m: norm=f"RAT-{int(m.group(1)):03d}"
    found=next((f for f in findings if f.get("id","").upper()==norm), None)
    if not found:
        found=next((f for f in findings if f.get("id","").lower()==str(target).lower()), None)
    if not found:
        print(f"\033[91m Finding {target} not found. Run `php artisan rat:show` to list all.\033[0m")
        return 1
    render_banner(with_image=True, compact=False)
    sev=found.get("severity","info").upper()
    col={"CRITICAL":"91","HIGH":"93","MEDIUM":"96","LOW":"94"}.get(sev,"90")
    print(f"\n  \033[{col};1m🐀 {found.get('id',target)}\033[0m  \033[{col};1m{sev}\033[0m\n")
    print(f"  \033[97m{found.get('title','')}\033[0m")
    if found.get("description") and found["description"]!=found.get("title"):
        print(f"  \033[90m{found.get('description')}\033[0m")
    print(f"\n  \033[97;1mENTRY POINT\033[0m\n  \033[96m{found.get('entry','—')}\033[0m")
    print(f"\n  \033[97;1mSOURCE\033[0m\n  \033[93m{found.get('source','—')}\033[0m")
    print(f"\n  \033[97;1mFLOW\033[0m\n")
    print("  \033[90mHTTP Request\033[0m\n  \033[90m    │\033[0m")
    for idx,node in enumerate(found.get("flow",[])):
        is_last= idx==len(found.get("flow",[]))-1
        box_col="91" if is_last else "97"
        print(f"  \033[90m    ▼\033[0m")
        print(f"  \033[{box_col}m┌───────────────────┐\033[0m")
        print(f"  \033[{box_col}m│ {node[:17]:17} │\033[0m")
        print(f"  \033[{box_col}m└────────┬──────────┘\033[0m")
        if not is_last: print(f"  \033[90m         │\033[0m")
    print(f"  \033[90m         ▼\033[0m\n  \033[90m    Filesystem / Sink\033[0m\n")
    print("  \033[97;1mWHY RAT FLAGGED THIS\033[0m\n")
    why=found.get("why") or found.get("description") or ""
    import textwrap
    for line in textwrap.wrap(why or "User-controlled input reaches a sensitive sink without a clearly identified security boundary.", 68):
        print(f"  \033[90m{line}\033[0m")
    print(f"\n  \033[97;1mCONFIDENCE\033[0m")
    conf=found.get("confidence","high").upper()
    bar={"HIGH":"██████████████████░░","MEDIUM":"████████████░░░░░░░░","LOW":"██████░░░░░░░░░░░░░░"}.get(conf,"████████░░░░░░░░░░░░")
    print(f"  \033[96m{bar}\033[0m  \033[97m{conf}\033[0m\n")
    if found.get("recommendations"):
        print("  \033[97;1mRECOMMENDATION\033[0m\n  \033[90mReview whether:\033[0m")
        for r in found["recommendations"]:
            print(f"    \033[90m•\033[0m \033[97m{r}\033[0m")
        print()
    if found.get("file"):
        print("  \033[97;1mLOCATION\033[0m")
        print(f"  \033[90m{found.get('file')}:{found.get('line','')}\033[0m\n")
        abs_p=pathlib.Path.cwd()/found.get("file")
        if abs_p.exists():
            lines=abs_p.read_text(errors="ignore").splitlines()
            ln=max(1,int(found.get("line",1))-2)
            print("  \033[90mCode:\033[0m")
            for i in range(ln, min(ln+7, len(lines)+1)):
                code=lines[i-1]
                marker="›" if i==int(found.get("line",1)) else " "
                print(f"  {marker} \033[90m{i:3}\033[0m {code}")
            print()
    return 0

def main():
    parser=argparse.ArgumentParser(prog="rat.py", description="RAT — Python-native Laravel Security & Behavior Analyzer")
    subparsers=parser.add_subparsers(dest="command")

    # default scan parser (also top-level options)
    def add_scan_opts(p):
        p.add_argument("--format", default="table", choices=["table","json","ndjson","sarif","html","markdown"], help="Output format (Plan #17, #18: SARIF/HTML/Markdown)")
        p.add_argument("--json", action="store_true", help="Alias for --format=json")
        p.add_argument("--ci", action="store_true", help="CI mode (Plan #16: exit 0/1/2)")
        p.add_argument("--fail-on", default=None, help="Override fail_on severity")
        p.add_argument("--no-image", action="store_true", help="Disable banner image")
        p.add_argument("--compact", action="store_true", help="Compact banner")
        p.add_argument("--all", action="store_true", help="Scan whole codebase (all PHP — recommended)")
        p.add_argument("--laravel", action="store_true", help="Scan Laravel lot (monolith + modular + microservices)")
        p.add_argument("--security", action="store_true", help="Security scan — Vulnerability & attack-surface")
        p.add_argument("--deep", action="store_true", help="Deep security scan — Advanced data-flow + behavior")
        p.add_argument("--path", default=None, help="Comma-separated paths to scan (custom)")
        p.add_argument("--exclude", default=None, help="Comma-separated exclude patterns")
        p.add_argument("--flush-cache", action="store_true", help="Flush incremental AST/cache (Plan #15)")
        return p

    # top-level scan options for `python3 rat.py` without subcommand
    add_scan_opts(parser)

    # show
    p_show=subparsers.add_parser("show", help="Show findings")
    p_show.add_argument("id", nargs="?", default=None, help="Finding ID or severity filter")
    p_show.add_argument("--format", default="table", choices=["table","json"])
    p_show.add_argument("--no-image", action="store_true")

    # flow
    p_flow=subparsers.add_parser("flow", help="Visualize flow for a route")
    p_flow.add_argument("route", help='Route e.g. "POST /api/import"')
    p_flow.add_argument("--depth", type=int, default=8)
    p_flow.add_argument("--format", default="table", choices=["table","json"])
    p_flow.add_argument("--no-image", action="store_true")

    # why
    p_why=subparsers.add_parser("why", help="Explain why a class has access")
    p_why.add_argument("target", help="Class e.g. UserController")
    p_why.add_argument("--depth", type=int, default=6)
    p_why.add_argument("--format", default="table", choices=["table","json"])
    p_why.add_argument("--no-image", action="store_true")

    # impact
    p_imp=subparsers.add_parser("impact", help="Show impact for a file/class")
    p_imp.add_argument("target", help="File e.g. User.php")
    p_imp.add_argument("--format", default="table", choices=["table","json"])
    p_imp.add_argument("--no-image", action="store_true")

    # parse
    args=parser.parse_args()

    if args.command=="show":
        return cmd_show(args)
    # add flow/why/impact minimal python versions that reuse load_last + python_rat graph (php artisan wrappers)
    if args.command=="flow":
        data=load_last()
        if not data:
            print("No scan yet — run `php artisan rat --all` first.")
            return 1
        # reuse graph file to display
        from python_rat.graph import ApplicationGraph, Node, Edge
        g=ApplicationGraph()
        for n in data.get("graph",{}).get("nodes",[]): g.add_node(Node(id=n["id"],type=n["type"],name=n["name"],file=n.get("file",""),line=n.get("line",0),meta=n.get("meta",{})))
        for e in data.get("graph",{}).get("edges",[]): g.add_edge(Edge(frm=e["from"],to=e["to"],kind=e["kind"],label=e.get("label","")))
        # find route
        route_arg=args.route.strip('"\'')
        found=None
        for n in g.nodes_by_type("Route"):
            if n.name.lower()==route_arg.lower():
                found=n; break
        if not found:
            # try uri substring
            for n in g.nodes_by_type("Route"):
                if route_arg.lower() in n.name.lower():
                    found=n; break
        if not found:
            print(f"\033[91mRoute [{args.route}] not found.\033[0m")
            for n in g.nodes_by_type("Route")[:10]: print(f"  \033[96m{n.name}\033[0m")
            return 1
        if args.format=="json":
            queue=[(found.id,0)]; visited={found.id:True}; levels={0:[found]}
            edges=[]
            while queue:
                cur,d=queue.pop(0)
                if d>=args.depth: continue
                for e in g.outgoing(cur):
                    edges.append(e.to_dict())
                    if e.to not in visited:
                        visited[e.to]=True
                        nn=g.get_node(e.to)
                        if nn:
                            levels.setdefault(d+1,[]).append(nn)
                            queue.append((e.to,d+1))
            print(json.dumps({"entry":found.to_dict(),"trace":{"levels":{k:[n.to_dict() for n in v] for k,v in levels.items()},"edges":edges}}, indent=2))
            return 0
        if not args.no_image: render_banner()
        print(f"\n  \033[97;1m🐀 FLOW\033[0m\n\n  \033[96;1m{found.name}\033[0m\n")
        queue=[(found.id,0)]; visited={found.id:True}; levels={0:[found]}
        while queue:
            cur,d=queue.pop(0)
            if d>=args.depth: continue
            for e in g.outgoing(cur):
                if e.to not in visited:
                    visited[e.to]=True
                    nn=g.get_node(e.to)
                    if nn:
                        levels.setdefault(d+1,[]).append(nn)
                        queue.append((e.to,d+1))
        print(f"  \033[97m┌───────────────────┐\033[0m\n  \033[97m│ {found.name[:17]:17} │\033[0m \033[90mRoute\033[0m\n  \033[97m└────────┬──────────┘\033[0m")
        for lvl in sorted(levels):
            if lvl==0: continue
            nodes=levels[lvl]
            print(f"  \033[90m         │\033[0m")
            if len(nodes)==1:
                n=nodes[0]
                col={"External":"93","Database":"94","Filesystem":"91"}.get(n.type,"97")
                print(f"  \033[90m         ▼\033[0m")
                print(f"  \033[{col}m┌───────────────────┐\033[0m")
                print(f"  \033[{col}m│ {n.name[:17]:17} │\033[0m \033[90m{n.type}\033[0m")
                print(f"  \033[{col}m└────────┬──────────┘\033[0m")
            else:
                print(f"  \033[90m         ├──┬── Branch ({len(nodes)})\033[0m")
                for n in nodes:
                    col={"External":"93","Database":"94","Filesystem":"91"}.get(n.type,"97")
                    print(f"  \033[90m         │\033[0m  \033[{col}m▶ {n.name[:16]:16}\033[0m \033[90m{n.type}\033[0m")
                print(f"  \033[90m         │\033[0m")
        print()
        return 0
    if args.command in ("why","impact"):
        # delegate to show simple placeholder via graph
        print(f"`php artisan rat:{args.command} {getattr(args,'target','')}` — Python graph query (read last.json). Run `php artisan rat --all` first then re-run.")
        # Implement minimal why/impact via analyzer graph reuse similar to flow
        data=load_last()
        if not data:
            print("No scan data."); return 1
        from python_rat.graph import ApplicationGraph, Node, Edge
        g=ApplicationGraph()
        for n in data.get("graph",{}).get("nodes",[]): g.add_node(Node(id=n["id"],type=n["type"],name=n["name"],file=n.get("file",""),line=n.get("line",0),meta=n.get("meta",{})))
        for e in data.get("graph",{}).get("edges",[]): g.add_edge(Edge(frm=e["from"],to=e["to"],kind=e["kind"],label=e.get("label","")))
        target=getattr(args,"target")
        # find best node
        cand=None
        base=pathlib.Path(target).stem
        for n in g.nodes.values():
            if n.name.lower()==target.lower() or n.name.lower()==base.lower():
                cand=n; break
        if not cand:
            for n in g.nodes.values():
                if target.lower() in n.name.lower():
                    cand=n; break
        if not cand:
            print(f"\033[91mTarget [{target}] not found.\033[0m")
            for n in list(g.nodes.values())[:10]: print(f"  \033[96m{n.name}\033[0m ({n.type})")
            return 1
        if args.format=="json":
            print(json.dumps({"target":cand.to_dict(),"outgoing":[e.to_dict() for e in g.outgoing(cand.id)],"incoming":[e.to_dict() for e in g.incoming(cand.id)]}, indent=2))
            return 0
        if not getattr(args,"no_image",False): render_banner()
        print(f"\n  \033[97;1mWHY DOES {cand.name.upper()} HAVE ACCESS?\033[0m\n")
        print(f"  \033[90mTarget:\033[0m \033[97;1m{cand.name}\033[0m \033[90m({cand.type}) {cand.file}\033[0m\n")
        outs=g.outgoing(cand.id)
        if outs:
            print("  \033[97;1mDEPENDENCY TRAIL (outgoing)\033[0m")
            for e in outs[:10]:
                t=g.get_node(e.to)
                print(f"    \033[96m{cand.name}\033[0m \033[90m{e.kind}\033[0m \033[97m{t.name if t else e.to}\033[0m")
        else:
            print("  \033[90mNo outgoing dependencies.\033[0m")
        if args.command=="impact":
            imp=g.impact_for(cand.id)
            print(f"\n  \033[97;1mIMPACT\033[0m  \033[93m{imp['score']}\033[0m")
            print(f"  Direct: {imp['direct_by_type']}  Indirect: {imp['indirect_by_type']}")
        return 0

    # default: scan
    return handle_scan(args)

if __name__=="__main__":
    sys.exit(main())
