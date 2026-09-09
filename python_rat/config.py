import re
import pathlib

DEFAULT_EXCLUDE = ["vendor","storage","bootstrap/cache","node_modules","public",".git",".idea",".vscode","tests","tests_python",".rat"]
DEFAULT_LARAVEL_LOT = ["app","routes","config","database","resources","Modules","modules","Domain","domain","Domains","src","packages","services","Services","apps","microservices","tests"]

def load_config(project_root: pathlib.Path) -> dict:
    """Parse config/rat.php via regex (no PHP execution needed). Falls back to defaults."""
    p = project_root / "config/rat.php"
    if not p.exists():
        return {"fail_on":"high","paths":["."],"exclude":DEFAULT_EXCLUDE,"analysis":{"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True},"baseline":str(project_root/".rat.baseline.json")}
    text=p.read_text(errors="ignore")
    # extract 'paths' => [ ... ]
    paths=["."]
    m=re.search(r"'paths'\s*=>\s*\[(.*?)\]", text, re.S)
    if m:
        inside=m.group(1)
        # collect quoted strings
        vals=re.findall(r"['\"]([^'\"]+)['\"]", inside)
        if vals:
            paths=vals
    # exclude
    exclude=DEFAULT_EXCLUDE
    m=re.search(r"'exclude'\s*=>\s*\[(.*?)\]", text, re.S)
    if m:
        vals=re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
        if vals:
            exclude=vals
    # fail_on
    fail_on="high"
    m=re.search(r"'fail_on'\s*=>\s*['\"]([^'\"]+)['\"]", text)
    if m: fail_on=m.group(1).lower()
    else:
        # maybe env('RAT_FAIL_ON', 'high')
        mm=re.search(r"env\s*\(\s*['\"]RAT_FAIL_ON['\"]\s*,\s*['\"]([^'\"]+)['\"]", text)
        if mm: fail_on=mm.group(1)
    # llm section (Plan: LLM false-positive reduction via oprouter)
    llm={}
    m=re.search(r"'llm'\s*=>\s*\[(.*?)\]\s*,?\s*\)", text, re.S)
    if not m:
        m=re.search(r"['\"]llm['\"]\s*=>\s*\[(.*?)\]", text, re.S)
    if m:
        block=m.group(1)
        # enabled
        em=re.search(r"['\"]enabled['\"]\s*=>\s*(env\s*\(\s*['\"]RAT_LLM['\"]\s*,\s*(true|false)|true|false)", block)
        if em:
            ev=em.group(1).lower()
            llm["enabled"]= ("true" in ev) or ("env" in ev and "true" in ev)
        # model
        mm=re.search(r"['\"]model['\"]\s*=>\s*['\"]([^'\"]+)['\"]", block)
        if mm: llm["model"]=mm.group(1)
        # min_confidence
        cm=re.search(r"['\"]min_confidence['\"]\s*=>\s*['\"]([^'\"]+)['\"]", block)
        if cm: llm["min_confidence"]=cm.group(1)
        # drop_false
        dm=re.search(r"['\"]drop_false['\"]\s*=>\s*(true|false)", block)
        if dm: llm["drop_false"]= dm.group(1).lower()=="true"
        # api_key (optional; else env OPENROUTER_API_KEY)
        km=re.search(r"['\"]api_key['\"]\s*=>\s*['\"]([^'\"]+)['\"]", block)
        if km: llm["api_key"]=km.group(1)
        # endpoint (optional; default OpenRouter chat completions URL)
        em2=re.search(r"['\"]endpoint['\"]\s*=>\s*['\"]([^'\"]+)['\"]", block)
        if em2: llm["endpoint"]=em2.group(1)
    cfg={"fail_on":fail_on,"paths":paths,"exclude":exclude,"analysis":{"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True},"baseline":str(project_root/".rat.baseline.json")}
    if llm: cfg["llm"]=llm
    return cfg

def resolve_scope(project_root: pathlib.Path, cfg: dict, args) -> dict:
    """
    Mirror PHP RatCommand::resolveScanScope logic for Python CLI.
    Supports --all, --laravel, --security, --deep, --path, interactive chooser.
    Order: --deep > --security > --all > --laravel > --path > interactive > config default
    """
    # Normalize args (argparse namespace or dict)
    def opt(name): 
        if isinstance(args, dict): return args.get(name)
        return getattr(args, name, None)
    deep=bool(opt("deep"))
    security=bool(opt("security"))
    all_=bool(opt("all"))
    laravel=bool(opt("laravel"))
    path_opt=opt("path")
    # Explicit flags
    if deep:
        cfg["paths"]=["."]
        cfg["analysis"]={"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True,"security":True,"deep":True}
        cfg["depth"]=12
        return cfg
    if security:
        cfg["paths"]=["."]
        cfg["analysis"]={"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True,"security":True}
        return cfg
    if all_:
        cfg["paths"]=["."]
        return cfg
    if laravel:
        cfg["paths"]=DEFAULT_LARAVEL_LOT[:]
        return cfg
    if path_opt:
        paths=[p.strip() for p in str(path_opt).split(",") if p.strip()]
        if paths:
            cfg["paths"]=paths
        return cfg
    # Interactive if TTY and not --ci/json
    is_json=opt("format") in ("json","ndjson") or bool(opt("json"))
    ci=bool(opt("ci"))
    # Check if stdin is tty and stdout is not json
    try:
        interactive=False
        import sys, os
        if not is_json and not ci and sys.stdin.isatty() and sys.stdout.isatty():
            # also check posix_isatty equivalent already covered
            interactive=True
        # fallback: if no explicit path and config was default, prompt unless non-interactive
        if interactive and not os.getenv("CI"):
            has_config=(project_root/"config/rat.php").exists()
            cfg=_interactive_choose(project_root, cfg, has_config)
            return cfg
    except Exception:
        pass
    if not cfg.get("paths"):
        cfg["paths"]=["."]
    return cfg

def _interactive_choose(project_root, cfg, has_config):
    print("  \033[90mScope selection (vendor/storage/public/.git always excluded):\033[0m")
    options=[
        ("all","Whole codebase (all PHP — recommended, respects exclude)"),
        ("laravel","Laravel lot (monolith + modular monolith + microservices monorepo)"),
        ("security","Security scan — Vulnerability & attack-surface analysis"),
        ("deep","Deep security scan — Advanced data-flow + behavior analysis"),
    ]
    if has_config and cfg.get("paths"):
        options.append(("config", f"Use config/rat.php ({', '.join(cfg['paths'])})"))
    options.append(("custom","Custom — you type paths"))
    # show numbered list
    for i,(key,desc) in enumerate(options):
        marker="→" if i==0 else " "
        print(f"  {marker} \033[90m[{i}]\033[0m \033[97m{key:8}\033[0m {desc}")
    print()
    # default is all or config if exists
    default_key="config" if has_config and cfg.get("paths") and any(k=="config" for k,_ in options) else "all"
    default_idx=next((i for i,(k,_) in enumerate(options) if k==default_key),0)
    try:
        choice=input(f"  What should RAT scan? [{default_idx}] (default {default_key}): ").strip()
        if choice=="":
            sel=default_key
        elif choice.isdigit() and 0 <= int(choice) < len(options):
            sel=options[int(choice)][0]
        elif choice in [k for k,_ in options]:
            sel=choice
        else:
            # try to match prefix
            sel=default_key
            for k,_ in options:
                if choice.lower() in k.lower():
                    sel=k; break
        print(f"  \033[90mSelected:\033[0m \033[97m{sel}\033[0m")
    except (EOFError, KeyboardInterrupt):
        print()
        sel=default_key

    if sel=="all":
        cfg["paths"]=["."]
    elif sel=="laravel":
        cfg["paths"]=DEFAULT_LARAVEL_LOT[:]
    elif sel=="security":
        cfg["paths"]=["."]
        cfg["analysis"]={"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True,"security":True}
        print("  \033[38;2;139;92;246m🐀 RAT // SECURITY SCAN\033[0m")
    elif sel=="deep":
        cfg["paths"]=["."]
        cfg["analysis"]={"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True,"security":True,"deep":True}
        cfg["depth"]=12
        print("  \033[38;2;139;92;246m🐀 RAT // DEEP SECURITY SCAN\033[0m")
    elif sel=="config":
        pass
    elif sel=="custom":
        custom=input("  Enter comma-separated paths (e.g. app,Modules,packages) [app,routes]: ").strip()
        if not custom: custom="app,routes"
        cfg["paths"]=[p.strip() for p in custom.split(",") if p.strip()]
        if not cfg["paths"]: cfg["paths"]=["."]
    print(f"  \033[90mScanning:\033[0m \033[97m{', '.join(cfg['paths'])}\033[0m\n")
    return cfg
