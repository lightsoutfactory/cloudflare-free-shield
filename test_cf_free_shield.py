"""Tests against a fake Cloudflare API (zones, custom rules with the Free plan's limit of five).

    python3 -m unittest test_cf_free_shield
"""
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"zones": {"alpha.example": "z1"}, "rulesets": {}, "seq": 0}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")

    def do_GET(self):
        if self.path.startswith("/zones?"):
            name = re.search(r"name=([^&]+)", self.path)
            zs = [(n, i) for n, i in STATE["zones"].items() if not name or n == name.group(1)]
            return self._json(200, {"success": True, "result": [{"name": n, "id": i} for n, i in zs],
                                    "result_info": {"total_pages": 1}})
        zid = self.path.split("/")[2]
        rs = STATE["rulesets"].get(zid)
        if not rs:
            return self._json(404, {"success": False, "errors": [{"code": 10003, "message": "not found"}]})
        self._json(200, {"success": True, "result": rs})

    def do_PUT(self):
        zid, rules = self.path.split("/")[2], self._body()["rules"]
        if len(rules) > 5:
            return self._json(400, {"success": False, "errors": [{"code": 20217, "message": "too many rules"}]})
        out = []
        for r in rules:
            STATE["seq"] += 1
            out.append({**r, "id": f"r{STATE['seq']}"})
        STATE["rulesets"][zid] = {"id": "rs-" + zid, "rules": out}
        self._json(200, {"success": True, "result": STATE["rulesets"][zid]})

    def do_PATCH(self):
        zid, rid = self.path.split("/")[2], self.path.split("/")[-1]
        rule = next(r for r in STATE["rulesets"][zid]["rules"] if r["id"] == rid)
        rule.update(self._body())
        self._json(200, {"success": True, "result": STATE["rulesets"][zid]})


SERVER = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
os.environ["CLOUDFLARE_API"] = f"http://127.0.0.1:{SERVER.server_address[1]}"
os.environ["CLOUDFLARE_API_TOKEN"] = "test"

import cf_free_shield as shield  # noqa: E402  (reads CLOUDFLARE_API at import)


class Test(unittest.TestCase):
    def setUp(self):
        STATE["rulesets"] = {"z1": {"id": "rs-z1", "rules": [{"id": "x", "description": "block admin", "action": "block",
                                                               "enabled": True, "expression": "ip.src eq 192.0.2.1"}]}}
        self.tmp = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp, True)

    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = shield.main(list(argv))
        return code, out.getvalue()

    def test_install_keeps_other_rules_backs_up_and_restores(self):
        code, out = self.run_cli("install", "alpha.example", "--dry-run")
        self.assertIn("would add fake browser", out)
        self.assertEqual(len(STATE["rulesets"]["z1"]["rules"]), 1)
        code, out = self.run_cli("install", "alpha.example")
        rules = STATE["rulesets"]["z1"]["rules"]
        self.assertEqual([r["description"].split(" - ")[0] for r in rules],
                         ["block admin", "cf-free-shield: fake browser", "cf-free-shield: scraper clouds",
                          "cf-free-shield: emergency"])
        self.assertEqual(self.run_cli("install", "alpha.example")[1].strip(), "alpha.example: up to date")
        self.run_cli("on", "alpha.example")
        self.assertTrue(STATE["rulesets"]["z1"]["rules"][-1]["enabled"])
        self.run_cli("install", "alpha.example", "--allow-ips", "198.51.100.7")
        self.assertTrue(STATE["rulesets"]["z1"]["rules"][-1]["enabled"], "a reinstall keeps the emergency rule on")
        self.run_cli("uninstall", "alpha.example")
        self.assertEqual([r["description"] for r in STATE["rulesets"]["z1"]["rules"]], ["block admin"])
        code, out = self.run_cli("restore", "alpha.example")
        self.assertIn("4 rules", out)

    def test_limit_and_no_asns(self):
        STATE["rulesets"]["z1"]["rules"] *= 3
        code, out = self.run_cli("install", "alpha.example")
        self.assertIn("not installed", out)
        code, out = self.run_cli("install", "alpha.example", "--asns", "")
        self.assertIn("add emergency", out)

    def test_rule_text(self):
        code, out = self.run_cli("rules")
        self.assertNotIn("ip.src in {}", out)
        self.assertIn("sec-fetch-mode", out)
        code, out = self.run_cli("rules", "--allow-ips", "203.0.113.7,2001:db8::/32")
        self.assertIn("not ip.src in {203.0.113.7 2001:db8::/32}", out)


if __name__ == "__main__":
    unittest.main()
