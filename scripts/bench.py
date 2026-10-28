#!/usr/bin/env python3
"""Mobile proxy benchmark - infrastructure test (CDN target).

A separate copy of the residential benchmark runner. The residential scripts in
residential-proxy-benchmark-2026 are not changed by this one.

Commands:
  setup     save provider credentials for the MOBILE products (file is readable only by you)
  check     find the working mobile format of each provider (1-3 requests per format)
  run       run the benchmark and save raw results to data/infra_*.csv
  summary   print tables (Success Rate with 95% CI, latency, Unique IPs, Geo Accuracy)
  schedule  print or install cron lines for repeated runs

Only the Python standard library is used.
"""
import argparse
import csv
import datetime
import getpass
import glob
import json
import math
import os
import random
import socket
import statistics
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

HOME = os.environ.get("BENCH_HOME") or os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HOME, "providers.json")
CHOICE_FILE = os.path.join(HOME, "format_choice.json")
DATA = os.path.join(HOME, "data")
LOGS = os.path.join(HOME, "logs")

DEFAULT_TARGET = "https://www.cloudflare.com/cdn-cgi/trace"
COUNTRIES = ["us", "de", "gb", "fr", "es", "br", "in", "pl", "ua", "tr", "vn", "id"]
STICKY_MIN = 30  # requested sticky session length, minutes

# Connection formats of the mobile products (see ../PROVIDERS.md).
# Placeholders: {login} {password} {cc} {CC} (country, lower/upper case),
# {sid} 8 chars a-z0-9, {SID} 16 chars A-Z0-9, {hex} 13 hex chars,
# {m} minutes, {s} seconds, {port} = port_base + session index (port-based sticky).
# 'pass' defaults to "{password}". For every provider 'check' tries the formats in
# order and saves the first one that works to format_choice.json.
PROVIDERS = {
    "floppydata": dict(
        label="Floppydata", hint="Subuser value, without 'user-'",
        rotating=[dict(host="geo.g-w.info:10080", user="user-{login}-type-mobile-country-{cc}"),
                  dict(host="geo.g-w.info:10080", user="user-{login}-type-mobile-country-{cc}-rotation--1")],
        sticky=[dict(host="geo.g-w.info:10080", user="user-{login}-type-mobile-session-{sid}-country-{cc}-rotation-{m}"),
                dict(host="geo.g-w.info:10080", user="user-{login}-type-mobile-session-{sid}-country-{cc}-rotation-0")]),
    "decodo": dict(
        label="Decodo", hint="Mobile user from Decodo dashboard > Mobile > Authentication",
        # Country hosts have their own ports (us.decodo.com:10000, de.decodo.com:20000, ...), so one
        # gateway with the country in the login is used for all 12 countries. With the mobile user it
        # exits on the same carrier networks as de.decodo.com:20000 (checked 2026-10-23).
        rotating=[dict(host="gate.decodo.com:7000", user="user-{login}-country-{cc}")],
        sticky=[dict(host="gate.decodo.com:7000", user="user-{login}-country-{cc}-session-{sid}-sessionduration-{m}")]),
    "oxylabs": dict(
        label="Oxylabs", hint="Mobile proxy user, without 'customer-'",
        rotating=[dict(host="pr.oxylabs.io:7777", user="customer-{login}-cc-{CC}")],
        sticky=[dict(host="pr.oxylabs.io:7777", user="customer-{login}-cc-{CC}-sessid-{sid}-sesstime-{m}")]),
    "evomi": dict(
        label="Evomi", hint="Mobile proxy username",
        rotating=[dict(host="mp.evomi.com:3000", user="{login}", **{"pass": "{password}_country-{CC}"})],
        sticky=[dict(host="mp.evomi.com:3000", user="{login}", **{"pass": "{password}_country-{CC}_session-{sid}_lifetime-{m}"}),
                dict(host="mp.evomi.com:3000", user="{login}", **{"pass": "{password}_country-{CC}_session-{sid}"})]),
    "soax": dict(
        label="SOAX", hint="not needed - press Enter; password = key of the 'mobile' package",
        rotating=[dict(host="proxy.soax.com:1337", user="country-{cc}-network-mob")],
        sticky=[dict(host="proxy.soax.com:1337", user="country-{cc}-network-mob-rotate-timed_{s}-session-{sid}"),
                dict(host="proxy.soax.com:1337", user="country-{cc}-network-mob-sessionid-{sid}-sessionlength-{s}")]),
    "dataimpulse": dict(
        label="DataImpulse", hint="Login of the MOBILE plan (new account)",
        rotating=[dict(host="gw.dataimpulse.com:823", user="{login}__cr.{cc}")],
        sticky=[dict(host="gw.dataimpulse.com:{port}", port_base=10000, user="{login}__cr.{cc}"),
                dict(host="gw.dataimpulse.com:823", user="{login}__cr.{cc};sessid.{sid}")]),
    "proxyempire": dict(
        label="ProxyEmpire", hint="Mobile login (starts with m_)",
        rotating=[dict(host="v2.proxyempire.io:5000", user="{login}-country-{cc}")],
        sticky=[dict(host="v2.proxyempire.io:5000", user="{login}-country-{cc}-sid-{sid}-ttl-{m}m")]),
    "nodemaven": dict(
        label="NodeMaven", hint="Same login as residential",
        rotating=[dict(host="gate.nodemaven.com:8080", user="{login}-country-{cc}-type-mobile")],
        sticky=[dict(host="gate.nodemaven.com:8080", user="{login}-country-{cc}-type-mobile-sid-{hex}-ttl-{m}m")]),
    "iproyal": dict(
        label="IPRoyal", hint="Login of the MOBILE product",
        rotating=[dict(host="geo.iproyal.com:12321", user="{login}", **{"pass": "{password}_country-{cc}"})],
        sticky=[dict(host="geo.iproyal.com:12321", user="{login}",
                     **{"pass": "{password}_country-{cc}_session-{sid}_lifetime-{m}m"})]),
    "byteful": dict(
        label="Byteful", hint="Proxy User from the Byteful dashboard (account number, underscore, name)",
        rotating=[dict(host="mobile.byteful.com:15242", user="{login}_c_{cc}"),
                  dict(host="mobile.byteful.com:8000", user="{login}_c_{cc}")],
        sticky=[dict(host="mobile.byteful.com:15730", user="{login}_c_{cc}_s_{SID}_ttl_{m}m"),
                dict(host="mobile.byteful.com:8000", user="{login}_c_{cc}_s_{SID}_ttl_{m}m"),
                dict(host="mobile.byteful.com:15730", user="{login}_c_{cc}_s_{SID}")]),
    "resiprox": dict(
        label="ResiProx", hint="Mobile username (starts with mobi_)",
        rotating=[dict(host="go.resiprox.com:5000", user="{login}-country-{cc}")],
        sticky=[dict(host="go.resiprox.com:5000", user="{login}-country-{cc}-sid-{sid}-ttl-{m}m"),
                dict(host="go.resiprox.com:5000", user="{login}-country-{cc}-sid-{sid}")]),
}

FIELDS = ["run_id", "ts_utc", "server", "provider", "test", "target",
          "country_req", "ok", "sec", "ip", "ipv", "geo_cf", "colo", "bytes", "err"]


# ----------------------------------------------------------------- config
def load_config():
    if not os.path.exists(CONFIG):
        sys.exit("No providers.json yet. Run:  python3 bench.py setup")
    with open(CONFIG) as f:
        return json.load(f)


def save_config(cfg):
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=1)
    os.chmod(CONFIG, 0o600)


def load_choice():
    if os.path.exists(CHOICE_FILE):
        with open(CHOICE_FILE) as f:
            return json.load(f)
    return {"rotating": {}, "sticky": {}}


def save_choice(choice):
    with open(CHOICE_FILE, "w") as f:
        json.dump(choice, f, indent=1)


def cmd_setup(args):
    cfg = json.load(open(CONFIG)) if os.path.exists(CONFIG) else {"providers": {}}
    print("Enter the credentials of the MOBILE products. Press Enter to keep the saved value or skip.")
    for key, prov in PROVIDERS.items():
        if args.providers and key not in args.providers:
            continue
        cur = cfg["providers"].get(key, {})
        print("\n%s" % prov["label"])
        state = "saved" if cur.get("login") else "empty"
        login = input("  Login (%s) [%s]: " % (prov["hint"], state)).strip()
        password = getpass.getpass("  Password (hidden while typing): ").strip()
        login = login or cur.get("login", "")
        password = password or cur.get("password", "")
        needs_login = any("{login}" in f["user"] for f in prov["rotating"])
        if password and needs_login and not login:
            print("  NOT SAVED: %s needs a login. Run  bench.py setup %s  again." % (prov["label"], key))
        elif password:
            cfg["providers"][key] = dict(login=login, password=password)
    save_config(cfg)
    print("\nSaved providers: %s" % (", ".join(sorted(cfg["providers"])) or "none"))
    print("File %s is readable only by the current user." % CONFIG)


# ---------------------------------------------------------------- network
def new_session(idx=0):
    """Random session values for one sticky session; idx is used by port-based formats."""
    rnd = random.SystemRandom()
    return dict(sid="".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(8)),
                SID="".join(rnd.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
                hex="".join(rnd.choice("0123456789abcdef") for _ in range(13)),
                idx=idx)


def fill(template, values):
    for k, v in values.items():
        template = template.replace("{%s}" % k, str(v))
    return template


def proxy_url(cred, fmt, cc, session=None, minutes=STICKY_MIN):
    """http://user:pass@host:port for one request (rotating) or one sticky session."""
    session = session or new_session()
    values = dict(login=cred.get("login", ""), cc=cc, CC=cc.upper(), m=minutes, s=minutes * 60,
                  port=fmt.get("port_base", 0) + session["idx"],
                  sid=session["sid"], SID=session["SID"], hex=session["hex"])
    user = fill(fmt["user"], values)
    pw = fill(fmt.get("pass", "{password}"), values).replace("{password}", cred["password"])
    host = fill(fmt["host"], values)
    return "http://%s:%s@%s" % (urllib.parse.quote(user, safe=""), urllib.parse.quote(pw, safe=""), host)


def opener_for(url):
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": url, "https": url}))


def rotating_format(key, choice=None):
    choice = choice if choice is not None else load_choice()
    i = choice["rotating"].get(key)
    if i is None:
        sys.exit("No working rotating format saved for %s. Run:  python3 bench.py check --providers %s" % (key, key))
    return PROVIDERS[key]["rotating"][i]


def make_opener(cred, key, cc, choice=None):
    return opener_for(proxy_url(cred, rotating_format(key, choice), cc))


def classify_error(e):
    if isinstance(e, urllib.error.HTTPError):
        return "http_%d" % e.code
    s = str(e).lower()
    if "407" in s:
        return "proxy_auth_407"
    if isinstance(e, socket.timeout) or "timed out" in s:
        return "timeout"
    if "tunnel connection failed" in s or "connect tunnel failed" in s:
        code = "".join(ch for ch in s.split("response")[-1] if ch.isdigit())[:3] if "response" in s \
            else s.split(":")[-1].strip().split(" ")[0]
        return "tunnel_failed_" + code if code.isdigit() else "tunnel_failed"
    if "reset" in s:
        return "conn_reset"
    if "refused" in s:
        return "conn_refused"
    if "ssl" in s or "certificate" in s:
        return "ssl_error"
    return "other: " + str(e)[:60]


def utcnow():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def trace(opener, target, timeout):
    """One Cloudflare trace request. Returns (fields, nbytes)."""
    req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=timeout) as r:
        body = r.read().decode(errors="replace")
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line), len(body)


def one_request(opener, run_id, server, provider, cc, target, timeout):
    t = time.time()
    row = dict(run_id=run_id, ts_utc=utcnow(), server=server, provider=provider,
               test="cdn", target=target, country_req=cc, ok=0, sec=0.0, ip="", ipv="",
               geo_cf="", colo="", bytes=0, err="")
    try:
        d, row["bytes"] = trace(opener, target, timeout)
        if d.get("ip"):
            row.update(ok=1, ip=d["ip"], ipv=6 if ":" in d["ip"] else 4,
                       geo_cf=d.get("loc", "").lower(), colo=d.get("colo", ""))
        else:
            row["err"] = "unexpected_response"
    except Exception as e:  # noqa: BLE001 - every failure is a data point
        row["err"] = classify_error(e)
    row["sec"] = round(time.time() - t, 3)
    return row


# ------------------------------------------------------------------ stats
def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def pctl(sorted_vals, q):
    n = len(sorted_vals)
    return sorted_vals[min(n - 1, max(0, math.ceil(q * n) - 1))]


def fmt_rate(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return "%.1f%% (%.1f-%.1f)" % (100.0 * k / n, 100 * lo, 100 * hi)


def stats(rs):
    good = [r for r in rs if r["ok"]]
    out = dict(n=len(rs), k=len(good))
    if good:
        t = sorted(r["sec"] for r in good)
        out["med"] = statistics.median(t)
        out["p90"] = pctl(t, 0.9)
        out["uniq"] = len(set(r["ip"] for r in good))
        out["geo"] = sum(1 for r in good if r["geo_cf"] == r["country_req"])
        out["v6"] = sum(1 for r in good if str(r["ipv"]) == "6")
    return out


def print_table(rows):
    by = defaultdict(list)
    for r in rows:
        by[r["country_req"]].append(r)
    order = [c for c in COUNTRIES if c in by] + sorted(c for c in by if c not in COUNTRIES)
    head = "%-8s| %-9s| %-24s| %-10s| %-8s| %-13s| %-11s| %-7s| %s" % (
        "Country", "Requests", "Success Rate (95% CI)", "Median, s", "P90, s",
        "Unique IPs", "Duplicates", "IPv6", "Geo Accuracy (Cloudflare)")
    print(head)
    print("-" * len(head))

    def line(label, s):
        if not s["k"]:
            print("%-8s| %-9d| %-24s| no successful requests" % (label, s["n"], fmt_rate(0, s["n"])))
            return
        print("%-8s| %-9d| %-24s| %-10.2f| %-8.2f| %-13s| %-11s| %-7s| %s" % (
            label, s["n"], fmt_rate(s["k"], s["n"]), s["med"], s["p90"],
            "%d/%d" % (s["uniq"], s["k"]),
            "%.1f%%" % (100.0 * (1 - s["uniq"] / s["k"])),
            "%.0f%%" % (100.0 * s["v6"] / s["k"]),
            fmt_rate(s["geo"], s["k"])))

    for c in order:
        line(c.upper(), stats(by[c]))
    print("-" * len(head))
    line("TOTAL", stats(rows))
    errs = Counter(r["err"] for r in rows if not r["ok"])
    if errs:
        print("Errors: " + ", ".join("%s x%d" % kv for kv in errs.most_common()))


def print_report(rows, title):
    print()
    print("=" * 100)
    print(title)
    print("=" * 100)
    print_table(rows)


# --------------------------------------------------------------- commands
def check_rotating(key, cred, args):
    """Two requests per format: both must answer, and two different IPs is a good sign."""
    for i, fmt in enumerate(PROVIDERS[key]["rotating"]):
        rows = [one_request(opener_for(proxy_url(cred, fmt, args.country)), "check", "check", key,
                            args.country, args.target, args.timeout) for _ in range(2)]
        ok = all(r["ok"] for r in rows)
        note = ""
        if ok:
            note = "2 different IPs" if rows[0]["ip"] != rows[1]["ip"] else "SAME IP twice - is it rotating?"
            note += ", cloudflare_country=%s" % rows[0]["geo_cf"]
        print("  rotating #%d %-58s %s  %s" % (i + 1, fill(fmt["host"], dict(cc=args.country)) + " " + fmt["user"][:36],
                                               "OK  " if ok else "FAIL", note or ", ".join(r["err"] for r in rows)))
        if ok:
            return i
    return None


def check_sticky(key, cred, args):
    """Three requests 3 s apart in one session must keep one IP; a new session should give another IP."""
    for i, fmt in enumerate(PROVIDERS[key]["sticky"]):
        ses = new_session(idx=0)
        ips, errs = [], []
        for _ in range(3):
            r = one_request(opener_for(proxy_url(cred, fmt, args.country, ses)), "check", "check", key,
                            args.country, args.target, args.timeout)
            ips.append(r["ip"])
            errs.append(r["err"])
            time.sleep(3)
        other = one_request(opener_for(proxy_url(cred, fmt, args.country, new_session(idx=1))), "check", "check",
                            key, args.country, args.target, args.timeout)
        ok = all(ips) and len(set(ips)) == 1
        if ok:
            note = "same IP x3" + ("" if other["ip"] and other["ip"] != ips[0] else ", but a new session gave the SAME IP - check!")
        else:
            note = ", ".join(sorted(set(e for e in errs if e))) or "IP changed within 9 s"
        print("  sticky   #%d %-58s %s  %s" % (i + 1, fmt["host"][:22] + " " + fmt["user"][:36],
                                               "OK  " if ok else "FAIL", note))
        if ok:
            return i
    return None


def check_countries(key, cred, fmt, args):
    """One request per test country with the chosen rotating format."""
    bad = []
    for cc in COUNTRIES:
        r = one_request(opener_for(proxy_url(cred, fmt, cc)), "check", "check", key, cc, args.target, args.timeout)
        if not r["ok"]:
            bad.append("%s (%s)" % (cc.upper(), r["err"]))
        elif r["geo_cf"] != cc:
            bad.append("%s (exit in %s)" % (cc.upper(), r["geo_cf"].upper()))
    print("  countries: %s" % ("all %d OK" % len(COUNTRIES) if not bad else "problems in " + ", ".join(bad)))


def cmd_check(args):
    cfg = load_config()["providers"]
    choice = load_choice()
    want = args.providers.split(",") if args.providers else sorted(cfg)
    for key in want:
        if key not in PROVIDERS:
            sys.exit("Unknown provider: %s (known: %s)" % (key, ", ".join(PROVIDERS)))
        if key not in cfg:
            print("\n%s: no credentials saved, skipped" % key)
            continue
        print("\n%s" % PROVIDERS[key]["label"])
        for kind, fn in (("rotating", check_rotating), ("sticky", check_sticky)):
            if args.only and args.only != kind:
                continue
            i = fn(key, cfg[key], args)
            if i is None:
                choice[kind].pop(key, None)
                print("  %s: NO WORKING FORMAT FOUND" % kind)
            else:
                choice[kind][key] = i
                if kind == "rotating" and args.all_countries:
                    check_countries(key, cfg[key], PROVIDERS[key]["rotating"][i], args)
    save_choice(choice)
    print("\nWorking rotating: %d, sticky: %d of %d providers. Saved to %s" % (
        len(choice["rotating"]), len(choice["sticky"]), len(cfg), CHOICE_FILE))


def cmd_run(args):
    cfg = load_config()["providers"]
    choice = load_choice()
    keys = args.providers.split(",") if args.providers else sorted(k for k in cfg if k in choice["rotating"])
    for k in keys:
        if k not in cfg:
            sys.exit("Unknown provider: %s (saved: %s)" % (k, ", ".join(sorted(cfg))))
        rotating_format(k, choice)
    countries = args.countries.split(",")
    run_id = args.run_id or time.strftime("%Y%m%d-%H%M", time.gmtime())
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, "infra_%s_%s.csv" % (args.server, run_id))
    total = args.n * len(countries) * len(keys)
    print("[%s] run %s on server '%s': %d providers x %d countries x %d requests = %d requests"
          % (utcnow(), run_id, args.server, len(keys), len(countries), args.n, total))
    rows = []
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        # countries are the outer loop and providers the inner one, so all
        # providers are measured at nearly the same time in every country
        for cc in countries:
            order = keys[:]
            random.shuffle(order)
            for key in order:
                opener = make_opener(cfg[key], key, cc, choice)
                with ThreadPoolExecutor(max_workers=args.workers) as ex:
                    batch = list(ex.map(
                        lambda i: one_request(opener, run_id, args.server, key, cc,
                                              args.target, args.timeout), range(args.n)))
                w.writerows(batch)
                f.flush()
                rows += batch
                ok = sum(r["ok"] for r in batch)
                print("[%s] %-12s %-3s %d/%d ok" % (utcnow(), key, cc.upper(), ok, args.n))
    print("[%s] finished, raw data in %s" % (utcnow(), path))
    for key in keys:
        print_report([r for r in rows if r["provider"] == key],
                     "Provider: %s | Server: %s | Run: %s | Target: %s | Rotation: every request"
                     % (key, args.server, run_id, args.target))


def load_rows(server=None, run=None, provider=None):
    rows = []
    for path in sorted(glob.glob(os.path.join(DATA, "infra_*.csv"))):
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                r["ok"] = int(r["ok"])
                r["sec"] = float(r["sec"])
                r["bytes"] = int(r["bytes"] or 0)
                if server and r["server"] != server:
                    continue
                if run and r["run_id"] != run:
                    continue
                if provider and r["provider"] != provider:
                    continue
                rows.append(r)
    return rows


def cmd_summary(args):
    rows = load_rows(args.server, args.run, args.provider)
    if not rows:
        sys.exit("No data found in %s" % DATA)
    groups = defaultdict(list)
    for r in rows:
        groups[(r["server"], r["provider"])].append(r)
    for (server, prov), rs in sorted(groups.items()):
        runs = sorted(set(r["run_id"] for r in rs))
        print_report(rs, "Provider: %s | Server: %s | Runs: %d (%s .. %s) | Target: %s | Rotation: every request"
                     % (prov, server, len(runs), runs[0], runs[-1], rs[0]["target"]))


def cmd_schedule(args):
    tag = "# mbench-infra"
    hours = [int(h) for h in args.hours.split(",")]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    lines = []
    for d in range(args.start_in_days, args.start_in_days + args.days):
        day = today + datetime.timedelta(days=d)
        for h in hours:
            at_utc = datetime.datetime(day.year, day.month, day.day, h, 0,
                                       tzinfo=datetime.timezone.utc)
            if at_utc <= datetime.datetime.now(datetime.timezone.utc):
                continue  # skip times that are already in the past
            at = at_utc.astimezone()
            lines.append("%d %d %d %d * cd %s && %s bench.py run --server %s --n %d >> %s 2>&1 %s"
                         % (at.minute, at.hour, at.day, at.month, HOME, sys.executable,
                            args.server, args.n, os.path.join(LOGS, "cron.log"), tag))
    print("Runs at %s UTC on %d day(s), starting %s:" % (
        ", ".join("%02d:00" % h for h in hours), args.days,
        today + datetime.timedelta(days=args.start_in_days)))
    for ln in lines:
        print("  " + ln)
    if not args.install:
        print("\nNothing installed. Add --install to write these into cron.")
        return
    os.makedirs(LOGS, exist_ok=True)
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    keep = [ln for ln in cur.stdout.splitlines() if tag not in ln] if cur.returncode == 0 else []
    new = "\n".join(keep + lines) + "\n"
    subprocess.run(["crontab", "-"], input=new, text=True, check=True)
    print("\nInstalled %d runs into cron. Check with:  crontab -l" % len(lines))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup")
    s.add_argument("providers", nargs="*", help="only these providers, e.g. byteful resiprox")
    s.set_defaults(fn=cmd_setup)

    s = sub.add_parser("check")
    s.add_argument("--country", default="us")
    s.add_argument("--providers", default="")
    s.add_argument("--only", choices=["rotating", "sticky"], default="")
    s.add_argument("--all-countries", action="store_true",
                   help="also send 1 request per test country with the working rotating format")
    s.add_argument("--target", default=DEFAULT_TARGET)
    s.add_argument("--timeout", type=float, default=30)
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("run")
    s.add_argument("--server", required=True, help="label of this test server, e.g. de, us, sg")
    s.add_argument("--n", type=int, default=100, help="requests per provider and country")
    s.add_argument("--workers", type=int, default=5)
    s.add_argument("--countries", default=",".join(COUNTRIES))
    s.add_argument("--providers", default="")
    s.add_argument("--target", default=DEFAULT_TARGET)
    s.add_argument("--timeout", type=float, default=30)
    s.add_argument("--run-id", default="")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("summary")
    s.add_argument("--server", default="")
    s.add_argument("--run", default="")
    s.add_argument("--provider", default="")
    s.set_defaults(fn=cmd_summary)

    s = sub.add_parser("schedule")
    s.add_argument("--server", required=True)
    s.add_argument("--days", type=int, default=3)
    s.add_argument("--hours", default="8,20", help="UTC hours, comma separated")
    s.add_argument("--start-in-days", type=int, default=1)
    s.add_argument("--n", type=int, default=100)
    s.add_argument("--install", action="store_true")
    s.set_defaults(fn=cmd_schedule)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
