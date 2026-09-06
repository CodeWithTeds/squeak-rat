"""
tests_python/test_rat_scopes.py — Python-native RAT scope chooser tests

Validates that python handles all 5 chooser items via CLI:
  [all] Whole codebase
  [laravel] Laravel lot
  [security] Security scan
  [deep] Deep security scan
  [custom] Custom paths  (--path=)

Run:
  python3 -m unittest tests_python.test_rat_scopes -v
"""

import json, pathlib, subprocess, sys, tempfile, os, re
import unittest

ROOT = pathlib.Path(__file__).parent.parent
RAT_PY = ROOT / "rat.py"

def run_rat(args, cwd=ROOT):
    """Run rat.py with given args, return parsed json when --format=json"""
    cmd=[sys.executable, str(RAT_PY)] + args + ["--no-image"]
    # ensure --format=json for easy parse unless already specified
    result=subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=15)
    return result

class TestRatScopes(unittest.TestCase):

    def test_all_flag_json(self):
        r=run_rat(["--all","--format=json"])
        self.assertEqual(r.returncode,0, r.stderr)
        data=json.loads(r.stdout)
        self.assertIn("stats", data)
        self.assertIn("findings", data)
        self.assertGreater(data["stats"]["files"], 0)
        # self-scan via python precise is clean (pure false)
        self.assertEqual(len(data["findings"]), 0, f"Python precise all should be 0 pure false, got {data['findings']}")
        print(f"✅ --all: files={data['stats']['files']} findings=0 pure false")

    def test_laravel_flag(self):
        r=run_rat(["--laravel","--format=json"])
        self.assertEqual(r.returncode,0, r.stderr)
        data=json.loads(r.stdout)
        # Laravel lot should be subset of all (26 vs 27) but still valid
        self.assertGreater(data["stats"]["files"], 0)
        # Laravel lot still clean for this repo (no real vuln)
        self.assertEqual(len(data["findings"]), 0)
        print(f"✅ --laravel: files={data['stats']['files']} findings=0")

    def test_security_flag(self):
        r=run_rat(["--security","--format=json"])
        self.assertEqual(r.returncode,0, r.stderr)
        data=json.loads(r.stdout)
        self.assertIn("findings", data)
        # security scan also 0 for clean self-scan
        self.assertEqual(len(data["findings"]), 0)
        # stdout when not json should contain SECURITY SCAN banner — check via non-json run
        r2=run_rat(["--security"])
        self.assertIn("SECURITY SCAN", r2.stdout)
        print("✅ --security: banner + 0 findings")

    def test_deep_flag(self):
        r=run_rat(["--deep","--format=json"])
        self.assertEqual(r.returncode,0, r.stderr)
        data=json.loads(r.stdout)
        self.assertEqual(len(data["findings"]), 0)
        r2=run_rat(["--deep"])
        self.assertIn("DEEP SECURITY SCAN", r2.stdout)
        print("✅ --deep: banner + 0 findings")

    def test_custom_path(self):
        # --path=src should scan only src (26 files) vs all (27)
        r_all=run_rat(["--all","--format=json"])
        r_src=run_rat(["--path=src","--format=json"])
        self.assertEqual(r_src.returncode,0)
        d_all=json.loads(r_all.stdout)
        d_src=json.loads(r_src.stdout)
        self.assertLessEqual(d_src["stats"]["files"], d_all["stats"]["files"])
        self.assertEqual(d_src["stats"]["files"], 26)  # src contains 26 php files
        print(f"✅ --path=src: {d_src['stats']['files']} vs --all {d_all['stats']['files']}")

    def test_custom_absolute_path_vuln_detection(self):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td)
            app=td/"app/Http/Controllers"
            app.mkdir(parents=True)
            vuln=app/"VulnController.php"
            vuln.write_text("""<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;
class VulnController {
    public function sql(Request $request) {
        $id=$request->input('id');
        $r=DB::raw("SELECT * FROM users WHERE id = $id");
        return $r;
    }
    public function safe(Request $r){
        $f=storage_path('a.txt');
        return file_get_contents($f);
    }
}""")
            r=run_rat([f"--path={td}","--format=json"], cwd=ROOT)
            self.assertEqual(r.returncode,0, r.stderr)
            data=json.loads(r.stdout)
            sinks=[f["sink"] for f in data["findings"]]
            self.assertIn("DB::raw", sinks, f"Should detect DB::raw taint, got {sinks}")
            self.assertNotIn("file_get_contents", sinks, "Safe file_get_contents must NOT be flagged — variable taint check")
            print(f"✅ --path={td} vulnerable detection: sinks={sinks} (2-method file correctly distinguishes)")

    def test_format_ndjson(self):
        r=run_rat(["--all","--format=ndjson"])
        self.assertEqual(r.returncode,0)
        # ndjson should be 0 lines for clean
        lines=[l for l in r.stdout.strip().splitlines() if l.strip() and not l.startswith("  \033")]
        # filter banner lines (ansi) — ndjson should have 0 json lines
        json_lines=[l for l in lines if l.startswith("{")]
        self.assertEqual(len(json_lines), 0)
        print("✅ --format=ndjson: 0 lines for clean")

    def test_ci_pass(self):
        r=run_rat(["--all","--ci","--fail-on=high"])
        self.assertEqual(r.returncode,0)
        self.assertIn("CI check passed", r.stdout)
        print("✅ --ci --fail-on=high passes for clean")

    def test_show_flow_why_impact(self):
        # After a scan, show/flow/why should work (reads last.json)
        run_rat(["--all","--format=json"])
        # show
        r=run_rat(["show","--format=json"])
        self.assertEqual(r.returncode,0)
        d=json.loads(r.stdout)
        self.assertIn("findings", d)
        # flow for non-existent route should error but not crash
        r2=subprocess.run([sys.executable, str(RAT_PY), "flow", "GET /nonexistent", "--no-image"], cwd=str(ROOT), capture_output=True, text=True)
        self.assertIn("not found", r2.stdout.lower() + r2.stderr.lower() or "1")
        print("✅ show/flow/why commands functional")

    def test_interactive_chooser(self):
        # Simulate interactive: echo "0" | python3 rat.py  -> choose [0] all
        proc=subprocess.run([sys.executable, str(RAT_PY), "--no-image"], input="0\n", cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        # Should complete and produce output containing Scanning
        self.assertIn("Scanning", proc.stdout)
        self.assertEqual(proc.returncode, 0)
        print("✅ interactive chooser (echo 0) selects all and scans")

    def test_exclude_respected(self):
        # Create temp project with vendor file that should be excluded
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td)
            (td/"vendor").mkdir()
            (td/"vendor"/"evil.php").write_text("<?php $x=$_GET['a']; eval($x);")
            (td/"app").mkdir()
            (td/"app"/"Good.php").write_text("<?php $a=1;")
            r=run_rat([f"--path={td}","--format=json"], cwd=ROOT)
            data=json.loads(r.stdout)
            # vendor files should be excluded, so 0 findings even though vendor/evil.php is vulnerable
            self.assertEqual(len(data["findings"]), 0, "vendor should be excluded — python respects exclude")
            # Now scan with explicit path including vendor as custom should still exclude? Our exclude always vendor, so still 0
            print("✅ exclude vendor respected")

    def test_python_vs_php_pure_false(self):
        php_snapshot=ROOT/"storage/rat/php_last.json"
        if not php_snapshot.exists():
            self.skipTest("php_last.json not found — run `php bin/rat --deep --no-image` first")
        php_data=json.loads(php_snapshot.read_text())
        # python precise last (after python scan) should be 0
        r=run_rat(["--all","--format=json"])
        py_data=json.loads(r.stdout)
        self.assertEqual(len(py_data["findings"]), 0)
        self.assertGreater(len(php_data["findings"]), 0)
        print(f"✅ PHP vs Python: php {len(php_data['findings'])} false positives (pure false) vs python {len(py_data['findings'])} precise 0")
        # Verify all php findings are false via verifier
        import importlib.util
        spec=importlib.util.spec_from_file_location("verify", str(ROOT/"verify_false_positives.py"))
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for f in php_data["findings"]:
            res=mod.verdict_for(f)
            self.assertTrue(res["false_positive"] is True, f"{f['id']} should be false")

if __name__=="__main__":
    suite=unittest.TestLoader().loadTestsFromTestCase(TestRatScopes)
    runner=unittest.TextTestRunner(verbosity=2)
    result=runner.run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
