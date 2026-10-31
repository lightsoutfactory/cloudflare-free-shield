#!/usr/bin/env python3
"""Cloudflare Free-plan shield: three WAF custom rules that stop most scraper floods at Cloudflare's edge.

    export CLOUDFLARE_API_TOKEN=...        # Zone: Read and Zone WAF: Edit for your zones
    python3 cf_free_shield.py rules                          the expressions, for your options
    python3 cf_free_shield.py status [zone|all]
    python3 cf_free_shield.py install <zone|all> [--dry-run]
    python3 cf_free_shield.py on|off <zone|all>              the emergency rule
    python3 cf_free_shield.py uninstall <zone|all>
    python3 cf_free_shield.py restore <zone> [backup.json]

1. fake browser (on): a GET whose user agent says Chrome but which sends no Sec-Fetch-Mode header gets a managed
   challenge. Every real Chrome has sent that header since 2019; a script that copies a Chrome user agent rarely does.
2. scraper clouds (on): a GET for a page from Alibaba, Tencent or Huawei Cloud (or the networks you pass with --asns)
   gets a managed challenge. People browse from home and mobile networks.
3. emergency (off): a GET with no cookie and no Referer gets a managed challenge. Switch it on during a flood: people
   with a cookie or arriving through a link pass untouched; a scraper that keeps no cookies does not.
All three let through Cloudflare's verified bots, user agents that name themselves as robots, --allow-ips, the paths in
--skip-paths and files that are not pages. Your own rules are kept, ahead of these. Every change saves the zone's rules
to ./shield-backups/<zone>/ first; `restore` puts the last saved set back.

No dependencies beyond Python 3.9. MIT licence. Part of Night Watch (https://lightsoutfactory.ai/kits/night-watch/),
which also watches your sites, switches the emergency rule on and off by itself, summarises firewall events and adds a
bot gate inside your app.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("CLOUDFLARE_API", "https://api.cloudflare.com/client/v4")
PHASE = "http_request_firewall_custom"
TAG = "cf-free-shield: "
NOT_PAGES = ("xml txt json rss atom ico png jpg jpeg webp avif gif svg css js map woff woff2 ttf otf pdf mp3 mp4 "
             "webm m4a zip webmanifest").split()
ROBOT_WORDS = ("bot", "crawl", "spider", "preview", "google", "lighthouse")
DEFAULT_ASNS = "45102 37963 132203 45090 136907 55990"  # Alibaba, Tencent, Huawei Cloud
KEEP = ("description", "action", "enabled", "expression", "action_parameters", "logging")


class CloudflareError(RuntimeError):
    pass


def call(token, method, path, body=None):
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": "cf-free-shield"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except ValueError:
            raise CloudflareError(f"{method} {path}: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CloudflareError(f"{method} {path}: {e}") from None


def errors(d):
    return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in d.get("errors") or []) or "no details"


def zones(token, which):
    if which != "all":
        d = call(token, "GET", f"/zones?name={which}")
        if not d.get("success") or not d.get("result"):
            raise CloudflareError(f"zone {which} not found with this token")
        return [(which, d["result"][0]["id"])]
    out, page = [], 1
    while True:
        d = call(token, "GET", f"/zones?status=active&per_page=50&page={page}")
        if not d.get("success"):
            raise CloudflareError(f"listing zones: {errors(d)}")
        out += [(z["name"], z["id"]) for z in d["result"]]
        if page >= int((d.get("result_info") or {}).get("total_pages") or 1):
            return sorted(out)
        page += 1


def entrypoint(token, zid):
    d = call(token, "GET", f"/zones/{zid}/rulesets/phases/{PHASE}/entrypoint")
    if d.get("success"):
        return d["result"]
    if any(e.get("code") == 10003 for e in d.get("errors") or []) or "not found" in errors(d).lower():
        return None
    raise CloudflareError(f"reading custom rules: {errors(d)}")


def put(token, zid, rules):
    d = call(token, "PUT", f"/zones/{zid}/rulesets/phases/{PHASE}/entrypoint", {"rules": rules})
    if not d.get("success"):
        raise CloudflareError(f"writing custom rules: {errors(d)}")


def _q(s):
    if '"' in s or "\\" in s:
        raise ValueError(f"not allowed in a rule: {s!r}")
    return f'"{s}"'


def rules(a):
    parts = ["not cf.client.bot"]
    if a.allow_ips:
        parts.append("not ip.src in {" + " ".join(a.allow_ips.replace(",", " ").split()) + "}")
    parts += [f"not lower(http.user_agent) contains {_q(w)}" for w in ROBOT_WORDS]
    parts += [f"not starts_with(http.request.uri.path, {_q(p)})" for p in a.skip_paths.replace(",", " ").split()]
    parts.append("not http.request.uri.path.extension in {" + " ".join(_q(x) for x in NOT_PAGES) + "}")
    common = " and ".join(parts)
    out = [{"description": f"{TAG}fake browser - Chrome without Sec-Fetch-Mode", "action": "managed_challenge",
            "enabled": True,
            "expression": ('http.request.method eq "GET" and http.user_agent contains "Chrome/"'
                           f' and not any(lower(http.request.headers.names[*])[*] eq "sec-fetch-mode") and {common}')}]
    asns = [x for x in a.asns.replace(",", " ").split() if x.isdigit()]
    if asns:
        out.append({"description": f"{TAG}scraper clouds - pages requested from cloud networks",
                    "action": "managed_challenge", "enabled": True,
                    "expression": f'http.request.method eq "GET" and ip.src.asnum in {{{" ".join(asns)}}} and {common}'})
    out.append({"description": f"{TAG}emergency - strangers without cookie or Referer (on during a flood)",
                "action": "managed_challenge", "enabled": False,
                "expression": f'http.request.method eq "GET" and http.cookie eq "" and http.referer eq "" and {common}'})
    return out


def ours(rule):
    return (rule.get("description") or "").startswith(TAG)


def kind(rule):
    return (rule.get("description") or "")[len(TAG):].split(" - ")[0].strip()


def keep(rule):
    return {k: rule[k] for k in KEEP if k in rule}


def backup(zone, ruleset):
    d = os.path.join("shield-backups", zone)
    os.makedirs(d, exist_ok=True)
    stamp, n = time.strftime("%Y%m%d-%H%M%S"), 0
    while os.path.exists(path := os.path.join(d, f"{stamp}-{n:02d}.json")):
        n += 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"zone": zone, "rules": [keep(r) for r in (ruleset or {}).get("rules") or []]}, fh, indent=1)
    return path


def install(a, token, zone, zid):
    rs = entrypoint(token, zid)
    now = (rs or {}).get("rules") or []
    theirs = [keep(r) for r in now if not ours(r)]
    old = {kind(r): r for r in now if ours(r)}
    mine, changes = [], []
    for r in rules(a):
        o = old.pop(kind(r), None)
        if o and kind(r) == "emergency":
            r = {**r, "enabled": o.get("enabled", False)}
        if not o:
            changes.append(f"add {kind(r)}")
        elif keep(o) != r:
            changes.append(f"update {kind(r)}")
        mine.append(r)
    changes += [f"remove {k}" for k in old]
    if len(theirs) + len(mine) > a.max_rules:
        return f"{zone}: not installed - {len(theirs)} other rules + {len(mine)} would exceed {a.max_rules} (Free = 5)"
    if not changes:
        return f"{zone}: up to date"
    if a.dry_run:
        return f"{zone}: would " + ", ".join(changes)
    saved = backup(zone, rs)
    put(token, zid, theirs + mine)
    return f"{zone}: " + ", ".join(changes) + f" (previous rules saved in {saved})"


def main(argv=None):
    p = argparse.ArgumentParser(description="Three free Cloudflare WAF rules against scraper floods.")
    p.add_argument("action", choices=["rules", "status", "install", "on", "off", "uninstall", "restore"])
    p.add_argument("zone", nargs="?", default="all")
    p.add_argument("file", nargs="?", help="restore: a backup file instead of the latest")
    p.add_argument("--allow-ips", default="", help="your own addresses or ranges, never challenged")
    p.add_argument("--skip-paths", default="/api/ /webhook", help="path prefixes never challenged")
    p.add_argument("--asns", default=DEFAULT_ASNS, help="cloud networks to challenge; empty for none")
    p.add_argument("--max-rules", type=int, default=5, help="custom rules your plan allows per zone (Free 5, Pro 20)")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    if a.action == "rules":
        for r in rules(a):
            print(f"{r['description']}  [{'on' if r['enabled'] else 'off'}]\n  {r['expression']}\n")
        return 0
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        print("set CLOUDFLARE_API_TOKEN (Zone: Read and Zone WAF: Edit)", file=sys.stderr)
        return 2
    if a.action == "restore" and a.zone == "all":
        print("restore works on one zone at a time", file=sys.stderr)
        return 2
    try:
        for zone, zid in zones(token, a.zone):
            rs = None
            if a.action == "status":
                now = (entrypoint(token, zid) or {}).get("rules") or []
                flags = ", ".join(f"{kind(r)}={'on' if r.get('enabled') else 'off'}" for r in now if ours(r))
                print(f"{zone:30s} {flags or 'not installed'}; {len([r for r in now if not ours(r)])} other rules")
            elif a.action == "install":
                print(install(a, token, zone, zid))
            elif a.action in ("on", "off"):
                rs = entrypoint(token, zid)
                rule = next((r for r in (rs or {}).get("rules") or [] if ours(r) and kind(r) == "emergency"), None)
                if not rule:
                    print(f"{zone}: not installed - run install first")
                    continue
                backup(zone, rs)
                d = call(token, "PATCH", f"/zones/{zid}/rulesets/{rs['id']}/rules/{rule['id']}",
                         {**keep(rule), "enabled": a.action == "on"})
                print(f"{zone}: emergency rule {a.action}" + ("" if d.get("success") else f" FAILED: {errors(d)}"))
            elif a.action == "uninstall":
                rs = entrypoint(token, zid)
                saved = backup(zone, rs)
                put(token, zid, [keep(r) for r in (rs or {}).get("rules") or [] if not ours(r)])
                print(f"{zone}: shield rules removed, others kept (saved in {saved})")
            elif a.action == "restore":
                d = os.path.join("shield-backups", zone)
                files = [a.file] if a.file else sorted(os.path.join(d, f) for f in os.listdir(d)) if os.path.isdir(d) else []
                if not files:
                    print(f"{zone}: no saved rules in {d}")
                    continue
                with open(files[-1], encoding="utf-8") as fh:
                    saved = json.load(fh)
                backup(zone, entrypoint(token, zid))
                put(token, zid, saved["rules"])
                print(f"{zone}: {len(saved['rules'])} rules from {files[-1]} restored")
    except CloudflareError as e:
        print(f"cf-free-shield: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
