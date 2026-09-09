"""
llm_filter.py — LLM-assisted false-positive reduction for RAT.

Uses OpenRouter as the AI provider to double-check each heuristic finding
against the actual source code, then drops findings the model confirms are
false positives (verdict: false).

Designed to degrade gracefully:
  - If `oprouter` and `requests` are both missing   -> LLM filtering disabled.
  - If no API key                                   -> LLM filtering disabled.
  - If a single API call fails                      -> that finding is KEPT (fail-safe).
  - Verdicts are cached by fingerprint so repeat scans re-use prior results.

Enable explicitly with  python3 rat.py --llm [--llm-model provider/model]
or permanently via config/rat.php:

    'llm' => [
        'enabled' => env('RAT_LLM', false),
        'model'   => env('RAT_LLM_MODEL', 'google/gemini-2.5-flash'),
        'api_key' => env('OPENROUTER_API_KEY'),      // optional; else env
        'endpoint' => 'https://openrouter.ai/api/v1/chat/completions',
        'min_confidence' => 'low',   // only ask model for findings >= this severity
        'drop_false' => true,        // remove confirmed false positives
    ],
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

try:
    from oprouter import OpenRouterClient
    _OPROUTER_AVAILABLE = True
except Exception:
    OpenRouterClient = None
    _OPROUTER_AVAILABLE = False

try:
    import requests

    _REQUESTS_AVAILABLE = True
except Exception:
    requests = None
    _REQUESTS_AVAILABLE = False


DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "google/gemini-2.5-flash"

_SYSTEM_PROMPT = (
    "You are a senior Laravel/PHP security code reviewer. You are given a static "
    "analysis security finding and the surrounding source code. Decide whether the "
    "finding is a REAL vulnerability (true positive) or a FALSE POSITIVE.\n"
    "\n"
    "Consider: whether user input truly reaches a dangerous sink, whether framework "
    "mitigations neutralise it (FormRequest validated()/safe() allow-lists, "
    "Gate/Policy authorization, Blade {{ }} escaping, parameterized queries, "
    "basename()/hashName() on file paths, hardcoded 'php://output', semantic "
    "'$next($request)' Closure calls, migrations/service-providers that are not "
    "HTTP endpoints), and whether severity is consistent with exploitability.\n"
    "\n"
    "Respond with ONLY strict JSON: "
    '{"verdict": "true"|"false", "reason": "<one short sentence>", '
    '"confidence": "high"|"medium"|"low"}'
    "\nverdict must be exactly the string true or false."
)


def _enabled_from(config: dict) -> bool:
    llm = config.get("llm") or {}
    return bool(llm.get("enabled", False))


def _model_from(config: dict, cli_model: str = "") -> str:
    llm = config.get("llm") or {}
    return cli_model or llm.get("model") or os.getenv("OPENROUTER_MODEL") or os.getenv("DEFAULT_MODEL") or DEFAULT_MODEL


def _min_severity_index(config: dict) -> int:
    llm = config.get("llm") or {}
    order = ["info", "low", "medium", "high", "critical"]
    want = str(llm.get("min_confidence", "low")).lower()
    return order.index(want) if want in order else order.index("low")


def fingerprint(finding: dict) -> str:
    raw = json.dumps(
        {
            "title": finding.get("title", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "sink": finding.get("sink", ""),
            "source": finding.get("source", ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _code_context(project_root: pathlib.Path, file: str, line: int, context_lines: int = 6) -> str:
    if not file:
        return ""
    p = pathlib.Path(project_root) / file
    if not p.exists():
        return ""
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except Exception:
        return ""
    start = max(0, int(line) - context_lines - 1)
    end = min(len(lines), int(line) + context_lines)
    out = []
    for i in range(start, end):
        num = i + 1
        marker = ">>" if num == int(line) else "  "
        out.append(f"{marker} {num}: {lines[i]}")
    return "\n".join(out)


def _build_user_prompt(finding: dict, context: str) -> str:
    parts = [
        "Finding:",
        f"- id: {finding.get('id','')}",
        f"- severity: {finding.get('severity','')}",
        f"- confidence: {finding.get('confidence','')}",
        f"- title: {finding.get('title','')}",
        f"- file: {finding.get('file','')}:{finding.get('line','')}",
        f"- entry: {finding.get('entry','')}",
        f"- source: {finding.get('source','')}",
        f"- sink: {finding.get('sink','')}",
        f"- flow: {', '.join(map(str, finding.get('flow', [])))}",
        f"- why: {finding.get('why','')}",
        "",
        "Relevant source code:",
        "```php",
        context if context else "(no source available)",
        "```",
    ]
    return "\n".join(parts)


def _parse_verdict(text: str) -> dict:
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    try:
        data = json.loads(cleaned)
    except Exception:
        m = re.search(r'"verdict"\s*:\s*"?(true|false)"?', text, re.I)
        if not m:
            return {"verdict": None, "reason": "unparseable", "confidence": "low"}
        return {
            "verdict": m.group(1).lower() == "true",
            "reason": "parsed verdict only",
            "confidence": "low",
        }
    v = str(data.get("verdict", "")).strip().lower()
    return {
        "verdict": None if v in ("", "unknown") else v == "true",
        "reason": data.get("reason", ""),
        "confidence": data.get("confidence", "medium"),
    }


class LLMClassifier:
    def __init__(self, project_root: pathlib.Path, config: dict, model: str = "", endpoint: str = ""):
        self.project_root = pathlib.Path(project_root).resolve()
        self.config = config
        self.llm_cfg = config.get("llm") or {}
        self.model = _model_from(config, model)
        self.endpoint = endpoint or str(self.llm_cfg.get("endpoint") or os.getenv("OPENROUTER_API_BASE") or DEFAULT_ENDPOINT)
        self.api_key = (
            os.getenv("OPENROUTER_API_KEY")
            or os.getenv("OPENROUTER_KEY")
            or str(self.llm_cfg.get("api_key") or "")
        )
        self.cache_path = self.project_root / ".rat.llm.cache.json"
        self._cache: Dict[str, dict] = {}
        self._loaded_cache = False

    @property
    def available(self) -> bool:
        if not _enabled_from(self.config):
            return False
        if not bool(self.api_key):
            return False

        return _OPROUTER_AVAILABLE or _REQUESTS_AVAILABLE

    def _load_cache(self) -> None:
        if self._loaded_cache:
            return
        self._loaded_cache = True
        if self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text(errors="ignore"))
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        try:
            self.cache_path.write_text(json.dumps(self._cache, indent=2))
        except Exception:
            pass

    def _complete(self, messages: list, max_tokens: int = 600) -> str:
        if not self.available:
            raise RuntimeError("LLM filtering is not available")

        if _OPROUTER_AVAILABLE and OpenRouterClient is not None:
            async def _run() -> str:
                async with OpenRouterClient(api_key=self.api_key, model=self.model) as client:
                    resp = await client.chat_completion(messages, model=self.model, stream=False)
                    if not resp.success:
                        raise RuntimeError(f"OpenRouter request failed: {resp.error}")
                    return resp.data["choices"][0]["message"]["content"]

            try:
                loop = asyncio.new_event_loop()
                try:
                    return loop.run_until_complete(_run())
                finally:
                    loop.close()
            except Exception:
                pass

        if _REQUESTS_AVAILABLE and requests is not None:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            data = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "max_tokens": max_tokens,
            }
            try:
                resp = requests.post(self.endpoint, headers=headers, json=data, timeout=60)
            except Exception:
                raise
            if resp.status_code != 200:
                raise RuntimeError(f"OpenRouter HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                body = resp.json()
                return body["choices"][0]["message"]["content"]
            except (KeyError, IndexError, ValueError):
                raise RuntimeError("OpenRouter response missing content")

        raise RuntimeError("No OpenRouter driver available (install oprouter or requests)")

    def classify(self, finding: dict) -> dict:
        fp = fingerprint(finding)
        self._load_cache()
        if fp in self._cache:
            cached = self._cache[fp]
            cached["fingerprint"] = fp
            cached["cached"] = True
            return cached

        if not self.available:
            return {"fingerprint": fp, "verdict": None, "reason": "not_available", "confidence": "low"}

        context = _code_context(self.project_root, finding.get("file", ""), finding.get("line", 0))
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(finding, context)},
        ]
        try:
            content = self._complete(messages)
            parsed = _parse_verdict(content)
        except Exception as e:
            parsed = {"verdict": None, "reason": f"error: {e}"[:200], "confidence": "low"}

        result = {
            "fingerprint": fp,
            "verdict": parsed.get("verdict"),
            "reason": parsed.get("reason", ""),
            "confidence": parsed.get("confidence", "low"),
        }
        if result["verdict"] is not None:
            self._cache[fp] = result
            self._save_cache()

        result["cached"] = False
        return result

    def filter(self, findings: List[dict], min_sev: str = "low", workers: int = 4) -> List[dict]:
        if not findings or not self.available:
            return findings

        sev_order = ["info", "low", "medium", "high", "critical"]
        min_idx = sev_order.index(min_sev) if min_sev in sev_order else sev_order.index("low")
        drop = bool(self.llm_cfg.get("drop_false", True))

        to_check = []
        cache_hits = 0
        self._load_cache()
        for f in findings:
            idx = sev_order.index(f.get("severity", "info")) if f.get("severity") in sev_order else 0
            if idx < min_idx:
                f["llm_verdict"] = None
                continue
            fp = fingerprint(f)
            if fp in self._cache and self._cache[fp].get("verdict") is not None:
                f["llm_verdict"] = self._cache[fp]["verdict"]
                f["llm_reason"] = self._cache[fp].get("reason", "")
                cache_hits += 1
                continue
            f["llm_verdict"] = True
            to_check.append(f)

        if to_check and workers > 1:
            def _one(f):
                try:
                    r = self.classify(f)
                    f["llm_verdict"] = r.get("verdict")
                    f["llm_reason"] = r.get("reason", "")
                except Exception:
                    f["llm_verdict"] = True

            with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
                list(ex.map(_one, [f for f in to_check]))
        else:
            for f in to_check:
                try:
                    r = self.classify(f)
                    f["llm_verdict"] = r.get("verdict")
                    f["llm_reason"] = r.get("reason", "")
                except Exception:
                    f["llm_verdict"] = True

        kept = []
        for f in findings:
            verdict = f.get("llm_verdict")
            if verdict is False and drop:
                continue
            kept.append(f)
        return kept


def filter_findings(project_root: pathlib.Path, config: dict, findings: list, model: str = "", workers: int = 4) -> list:
    if not _enabled_from(config):
        return findings
    has_key = bool(os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY"))
    has_driver = _OPROUTER_AVAILABLE or _REQUESTS_AVAILABLE
    if not (has_key and has_driver):
        return findings
    llm_cfg = config.get("llm") or {}
    try:
        cls = LLMClassifier(project_root, config, model=model)
        min_sev = str(llm_cfg.get("min_confidence", "low"))
        return cls.filter(findings, min_sev=min_sev, workers=workers)
    except Exception:
        return findings
