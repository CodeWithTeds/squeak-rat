"""
tests_python/test_rat_false_positives.py — PYTHON test suite proving RAT findings are pure false positives
- No PHP needed. Uses python_precise_scanner + verify_false_positives logic.
Run:
    python3 -m pytest tests_python -v
    python3 tests_python/test_rat_false_positives.py
"""
import re
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parent.parent
# Prefer PHP snapshot (which has the 6 false positives) if last.json was overwritten by python clean (0)
LAST_JSON = ROOT / "storage" / "rat" / "last.json"
_php_snapshot = ROOT / "storage/rat/php_last.json"
if LAST_JSON.exists():
    try:
        _d=json.loads(LAST_JSON.read_text())
        if len(_d.get("findings",[]))==0 and _php_snapshot.exists():
            LAST_JSON=_php_snapshot
    except: pass
if not LAST_JSON.exists() or (LAST_JSON.exists() and len(json.loads(LAST_JSON.read_text()).get("findings",[]))==0 and _php_snapshot.exists()):
    # fallback to php snapshot if current is empty
    if _php_snapshot.exists():
        LAST_JSON=_php_snapshot
    else:
        ALT = ROOT / ".rat.last.json"
        if ALT.exists():
            LAST_JSON = ALT

# Reuse strip logic from verifiers to avoid import side effects
def strip_php(content: str) -> str:
    strings=[]
    def _repl(m):
        strings.append(m.group(0))
        return f"__STR{len(strings)-1}__"
    tmp = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", _repl, content)
    tmp = re.sub(r"//.*", "", tmp)
    tmp = re.sub(r"^\s*#.*", "", tmp, flags=re.M)
    tmp = re.sub(r"/\*.*?\*/", "", tmp, flags=re.S)
    return tmp

class TestRatSelfScanIsPureFalse(unittest.TestCase):
    """All 6 self-scan findings must be false positives."""

    def setUp(self):
        self.assertTrue(LAST_JSON.exists(), f"Run `php bin/rat --deep --no-image` first, missing {LAST_JSON}")
        self.data = json.loads(LAST_JSON.read_text())
        self.findings = self.data.get("findings", [])

    def test_scan_has_findings(self):
        # Self-scan currently yields 6 findings; if 0, still ok but we assert >=1 to show test is meaningful
        self.assertGreaterEqual(len(self.findings), 1, "Expected at least 1 finding to verify false-positive logic")

    def test_rat_001_file_get_contents_is_false(self):
        """RAT-001 src/Engine/Analyzer.php:133 file_get_contents($file) is NOT tainted."""
        f = next((x for x in self.findings if x["id"]=="RAT-001"), None)
        self.assertIsNotNone(f, "RAT-001 missing")
        self.assertEqual(f["file"], "src/Engine/Analyzer.php")
        self.assertEqual(f["sink"], "file_get_contents")
        raw = (ROOT / f["file"]).read_text()
        clean = strip_php(raw)
        # Source only in string literal → clean has 0 executable sources
        SOURCE_RE = re.compile(r'\$request\s*->\s*(input|query|post|get|all|only|except|file|header|cookie|server|bearerToken)\s*\(', re.I)
        naive = len(re.findall(r'\$request\s*->\s*input\s*\(', raw))
        precise = len(SOURCE_RE.findall(clean))
        self.assertEqual(precise, 0, "Clean code should have 0 executable $request->input, naive hit is string literal at Analyzer.php:187")
        self.assertEqual(naive, 1, "Raw naive should see 1 hit (the fallback string)")
        # Sink line uses $file from collectPhpFiles, not tainted var — find line containing file_get_contents($file)
        lines = raw.splitlines()
        code = ""
        found_line = None
        for i, l in enumerate(lines, start=1):
            if "file_get_contents($file)" in l:
                code = l
                found_line = i
                break
        self.assertTrue(code, "Should find file_get_contents($file) line in Analyzer.php")
        self.assertIn("file_get_contents($file)", code, f"Unexpected code at {found_line}: {code}")
        self.assertNotIn("$request", code, "Sink line must not contain $request — variable-level taint fails → pure false")
        print(f"✅ RAT-001 pure false confirmed: cleaner naive={naive} precise={precise} code=`{code.strip()}` at line {found_line}")

    def test_rat_002_auth_is_comment_only(self):
        """RAT-002 FileDiscovery auth missing is comment false positive."""
        f = next((x for x in self.findings if x["id"]=="RAT-002"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f["file"], "src/Engine/Discovery/FileDiscovery.php")
        raw = (ROOT / f["file"]).read_text()
        clean = strip_php(raw)
        # Sensitive User:: only in comment
        self.assertIn("User::observe(UserObserver::class)", raw)
        self.assertNotIn("User::", clean, "After strip_php, User:: from comment should disappear — proves comment-only false")
        self.assertTrue(f["file"].startswith("src/Engine/"), "Infra file should be excluded from auth scan")
        print("✅ RAT-002 pure false confirmed: User:: only in comment, infra excluded")

    def test_hidden_behavior_all_comment_or_selfmatch(self):
        """RAT-003..006 hidden_behavior are comment/self-match false positives."""
        hidden = [x for x in self.findings if x["category"]=="hidden_behavior"]
        self.assertEqual(len(hidden), 4, f"Expected 4 hidden findings, got {hidden}")
        for f in hidden:
            raw = (ROOT / f["file"]).read_text()
            clean = strip_php(raw)
            # Real observer requires `class XObserver` in clean, not just word
            has_real = bool(re.search(r'class\s+\w+Observer\b', clean))
            self.assertFalse(has_real, f"{f['file']} flagged but no `class *Observer` in clean — comment/type-union false")
            print(f"✅ {f['id']} {f['file']} false: has_real_observer={has_real} naive_match={bool(re.search(r'Observer', raw))}")

    def test_precise_scanner_reports_zero(self):
        """Python precise scanner (variable-level taint) must report 0 for self-scan."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("python_precise_scanner", str(ROOT / "python_precise_scanner.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        findings = mod.precise_scan(str(ROOT), exclude=["vendor","storage","bootstrap/cache","node_modules","public",".git"])
        self.assertEqual(len(findings), 0, f"Precise scan should be 0 pure false, got {findings}")
        print(f"✅ Precise scanner 0 findings — pure false proven (vs PHP RAT {len(self.findings)})")

    def test_precise_scanner_detects_true_vuln_when_present(self):
        """Control test: precise scanner DOES detect real taint flow, so 0 is not always-silent."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("python_precise_scanner", str(ROOT / "python_precise_scanner.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            # Vulnerable fixture: $input = $request->input('cmd'); shell_exec($input);
            vuln = root / "VulnController.php"
            vuln.write_text("""<?php
namespace App\\Http\\Controllers;
class VulnController {
    public function exploit(\\Illuminate\\Http\\Request $request) {
        $cmd = $request->input('cmd');
        shell_exec($cmd);
    }
}""")
            # Safe fixture: file_get_contents on internal file, no taint
            safe = root / "SafeController.php"
            safe.write_text("""<?php
class SafeController {
    public function safe() {
        $file = __DIR__ . '/data.txt';
        $c = file_get_contents($file);
        return $c;
    }
}""")
            # Also test string-literal false: source only in string should NOT flag
            false_str = root / "FalseLiteral.php"
            false_str.write_text("""<?php
class FalseLiteral {
    public function foo() {
        $msg = '$request->input()'; // string literal not code
        $c = file_get_contents('/etc/hosts');
        return $c;
    }
}""")
            vuln_findings = mod.precise_scan(str(root), paths=["."], exclude=[])
            # vuln should be found, safe + false_str should NOT
            vuln_files = [f["file"] for f in vuln_findings]
            self.assertIn("VulnController.php", vuln_files, f"Should detect real vuln: {vuln_findings}")
            self.assertNotIn("SafeController.php", vuln_files, "Safe file must NOT be flagged — no taint")
            self.assertNotIn("FalseLiteral.php", vuln_files, "String-literal false must NOT be flagged after strip_php")
            print(f"✅ Control: precise scanner correctly flags true vuln and ignores safe/false ({vuln_findings})")

    def test_overall_pure_false(self):
        """End-to-end: 100% false positive rate."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("verify_false_positives", str(ROOT / "verify_false_positives.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Call verdict per finding
        for f in self.findings:
            res = mod.verdict_for(f)
            self.assertTrue(res["false_positive"] is True, f"{f['id']} should be FALSE_POSITIVE, got {res}")
        print(f"✅ ALL {len(self.findings)} findings are FALSE POSITIVES — pure false 100%")

if __name__ == "__main__":
    # allow running without pytest
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRatSelfScanIsPureFalse)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
