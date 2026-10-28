#!/usr/bin/env python3
"""Mobile proxy benchmark - target test (Google search + Instagram), as a phone browser.

Uses bench.py, providers.json and format_choice.json from the same folder.

Commands:
  run       run the target test and save raw results to data/targets_*.csv
  summary   print Target Success Rate tables from all saved results
  schedule  print or install cron lines for repeated runs

What counts as success:
  google     HTTP 200 from google.com that is not the /sorry/ CAPTCHA page. Google Search
             needs JavaScript since 2025, so a client without JavaScript gets a
             "turn on JavaScript" page or a consent page; both mean the IP was let in.
             Blocked IPs get the /sorry/ page or HTTP 429.
  instagram  the public profile page of @instagram opens (HTTP 200 with the profile data).
             Blocked or flagged IPs get HTTP 429 or a redirect to the login page. (The
             web_profile_info API answers "require_login" to every logged-out client since
             October 2026, so it is not used.)
A refusal by the proxy itself (CONNECT answered with 403, for example a target that the
provider does not allow) is saved as provider_restricted and is not a target failure.

curl_cffi is needed for the phone browser TLS fingerprint (--engine phone).
"""
import argparse
import csv
import datetime
import glob
import os
import random
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

try:
    from curl_cffi import requests as cffi_requests
except Exception:  # noqa: BLE001
    cffi_requests = None

GOOGLE_URL = "https://www.google.com/search?q=weather&hl=en&gl={cc}"
INSTAGRAM_URL = "https://www.instagram.com/instagram/"
# curl_cffi browser fingerprints tried in this order; the first one the installed
# curl_cffi knows is used
PHONE_FINGERPRINTS = ["chrome131_android", "chrome99_android", "safari18_0_ios", "safari17_2_ios"]
PHONE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
HEADERS = {
    "User-Agent": PHONE_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip",
}
MAX_BYTES = 3000000
FIELDS = ["run_id", "ts_utc", "server", "provider", "target", "country_req", "url",
          "ok", "status", "sec", "bytes", "result", "engine"]
TARGET_ORDER = ["google", "instagram"]
TARGET_LABEL = {"google": "Google search", "instagram": "Instagram profile"}
OK_RESULTS = ("success", "js_page", "consent")


# ---------------------------------------------------------------- requests
def judge(target, status, text, final_url):
    """Turn a response into one result label. ok = one of OK_RESULTS."""
    low = text.lower()  # the Instagram profile data sits deep in a ~900 KB page
    if target == "google":
        if "/sorry/" in final_url or "/sorry/index" in low or "unusual traffic" in low:
            return "captcha"
        if status == 429:
            return "blocked_429"
        if status == 200:
            if "consent.google" in final_url or "consent.google" in low[:5000]:
                return "consent"
            if 'id="search"' in low or 'id="rso"' in low or 'id="main"' in low:
                return "success"
            if "enablejs" in low or "httpservice/retry" in low or "<noscript" in low:
                return "js_page"
            return "bad_content"
    if target == "instagram":
        if "accounts/login" in final_url:
            return "login_wall"
        if "please wait a few minutes" in low:
            return "rate_limited"
        if status == 200:
            return "success" if ("profilepage" in low and '"username":"instagram"' in low) else "bad_content"
    if status in (401, 403, 429, 503):
        return "blocked_%d" % status
    if status == 404:
        return "not_found"
    return "http_%d" % status


def unzip(raw, encoding):
    if "gzip" in (encoding or "").lower():
        try:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw).decode(errors="replace")
        except Exception:  # noqa: BLE001
            return ""
    return raw.decode(errors="replace")


def headers_for(target):
    return {"Accept-Language": "en-US,en;q=0.9"}


def pick_fingerprint():
    """The first phone fingerprint that this curl_cffi version supports."""
    if cffi_requests is None:
        return None
    for fp in PHONE_FINGERPRINTS:
        try:
            cffi_requests.Session(impersonate=fp)
            return fp
        except Exception:  # noqa: BLE001
            continue
    return None


def fetch(proxy, target, url, timeout, engine, fingerprint):
    if engine == "phone":
        r = cffi_requests.get(url, impersonate=fingerprint, proxies={"http": proxy, "https": proxy},
                              timeout=timeout, headers=headers_for(target), allow_redirects=True)
        return r.status_code, len(r.content), r.text, str(r.url)
    req = urllib.request.Request(url, headers=dict(HEADERS, **headers_for(target)))
    opener = bench.opener_for(proxy)
    try:
        with opener.open(req, timeout=timeout) as r:
            status, raw, enc, final = r.status, r.read(MAX_BYTES), r.headers.get("Content-Encoding", ""), r.geturl()
    except urllib.error.HTTPError as e:
        status, raw, enc, final = e.code, e.read(MAX_BYTES), e.headers.get("Content-Encoding", ""), e.geturl()
    return status, len(raw), unzip(raw, enc), final


def one_target(proxy, run_id, server, provider, target, cc, url, timeout, engine, fingerprint):
    t = time.time()
    row = dict(run_id=run_id, ts_utc=bench.utcnow(), server=server, provider=provider,
               target=target, country_req=cc, url=url, ok=0, status=0, sec=0.0,
               bytes=0, result="", engine=fingerprint if engine == "phone" else engine)
    try:
        status, nbytes, text, final = fetch(proxy, target, url, timeout, engine, fingerprint)
        row.update(status=status, bytes=nbytes, result=judge(target, status, text, final))
        row["ok"] = int(row["result"] in OK_RESULTS)
    except Exception as e:  # noqa: BLE001 - every failure is a data point
        err = bench.classify_error(e)
        row["result"] = "provider_restricted" if err in ("tunnel_failed_403", "tunnel_failed_451") else err
    row["sec"] = round(time.time() - t, 3)
    return row


# ------------------------------------------------------------------ tables
def table(rows):
    by = defaultdict(list)
    for r in rows:
        by[(r["target"], r["country_req"])].append(r)
    head = "%-22s| %-8s| %-9s| %-30s| %-10s| %-8s| %-8s| %-8s| %-11s| %-6s| %s" % (
        "Target", "Country", "Requests", "Target Success Rate (95% CI)", "Median, s",
        "P90, s", "Captcha", "Blocked", "Restricted", "Other", "Avg KB/request")
    print(head)
    print("-" * len(head))

    def line(tname, cname, rs):
        restricted = sum(1 for r in rs if r["result"] == "provider_restricted")
        counted = [r for r in rs if r["result"] != "provider_restricted"]
        n, k = len(counted), sum(r["ok"] for r in counted)
        good = sorted(r["sec"] for r in counted if r["ok"])
        med = "%.2f" % statistics.median(good) if good else "-"
        p90 = "%.2f" % bench.pctl(good, 0.9) if good else "-"
        cap = sum(1 for r in counted if r["result"] == "captcha")
        blk = sum(1 for r in counted if r["result"].startswith("blocked_")
                  or r["result"] in ("rate_limited", "login_wall"))
        kb = sum(r["bytes"] for r in rs) / max(1, len(rs)) / 1024.0
        print("%-22s| %-8s| %-9d| %-30s| %-10s| %-8s| %-8d| %-8d| %-11d| %-6d| %.1f" % (
            tname, cname, n, bench.fmt_rate(k, n), med, p90, cap, blk, restricted,
            n - k - cap - blk, kb))

    for tg in [t for t in TARGET_ORDER if any(k[0] == t for k in by)]:
        ccs = [c for c in bench.COUNTRIES if (tg, c) in by] + \
              sorted(c for (t, c) in by if t == tg and c not in bench.COUNTRIES)
        for c in ccs:
            line(TARGET_LABEL[tg], c.upper(), by[(tg, c)])
        line(TARGET_LABEL[tg], "ALL", [r for r in rows if r["target"] == tg])
        print("-" * len(head))
    res = Counter(r["result"] for r in rows)
    print("Results: " + ", ".join("%s x%d" % kv for kv in res.most_common()))
    print("Restricted = the proxy refused the target (excluded from the Success Rate).")


def report(rows, title):
    print()
    print("=" * 140)
    print(title)
    print("=" * 140)
    table(rows)


# ---------------------------------------------------------------- commands
def cmd_run(args):
    fingerprint = None
    if args.engine == "phone":
        fingerprint = pick_fingerprint()
        if fingerprint is None:
            sys.exit("curl_cffi with a phone fingerprint is not available. Install curl_cffi or use --engine urllib")
    cfg = bench.load_config()["providers"]
    choice = bench.load_choice()
    keys = args.providers.split(",") if args.providers else sorted(k for k in cfg if k in choice["rotating"])
    for k in keys:
        if k not in cfg:
            sys.exit("Unknown provider: %s (saved: %s)" % (k, ", ".join(sorted(cfg))))
        bench.rotating_format(k, choice)
    countries = args.countries.split(",")
    ig_cc = set(c for c in args.instagram_countries.split(",") if c)
    run_id = args.run_id or time.strftime("%Y%m%d-%H%M", time.gmtime())
    os.makedirs(bench.DATA, exist_ok=True)
    path = os.path.join(bench.DATA, "targets_%s_%s.csv" % (args.server, run_id))

    def jobs(cc):
        out = []
        if args.n_google:
            out.append(("google", (args.google_url or GOOGLE_URL).replace("{cc}", cc), args.n_google))
        if args.n_instagram and cc in ig_cc:
            out.append(("instagram", args.instagram_url or INSTAGRAM_URL, args.n_instagram))
        return out

    total = sum(n for cc in countries for (_, _, n) in jobs(cc)) * len(keys)
    print("[%s] target run %s on server '%s': %d providers, %d requests in total, engine=%s"
          % (bench.utcnow(), run_id, args.server, len(keys), total, fingerprint or args.engine))
    rows = []
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for cc in countries:
            order = keys[:]
            random.shuffle(order)
            for key in order:
                fmt = bench.rotating_format(key, choice)
                for target, url, n in jobs(cc):
                    with ThreadPoolExecutor(max_workers=args.workers) as ex:
                        batch = list(ex.map(
                            lambda i: one_target(bench.proxy_url(cfg[key], fmt, cc), run_id, args.server, key,
                                                 target, cc, url, args.timeout, args.engine, fingerprint),
                            range(n)))
                    w.writerows(batch)
                    f.flush()
                    rows += batch
                    print("[%s] %-12s %-3s %-10s %d/%d ok" % (
                        bench.utcnow(), key, cc.upper(), target, sum(r["ok"] for r in batch), n))
    print("[%s] finished, raw data in %s" % (bench.utcnow(), path))
    for key in keys:
        report([r for r in rows if r["provider"] == key],
               "Provider: %s | Server: %s | Run: %s | Targets: Google search, Instagram | Rotation: every request"
               % (key, args.server, run_id))


def load_rows(server="", run="", provider=""):
    rows = []
    for p in sorted(glob.glob(os.path.join(bench.DATA, "targets_*.csv"))):
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                r["ok"] = int(r["ok"])
                r["sec"] = float(r["sec"])
                r["bytes"] = int(r["bytes"] or 0)
                if (server and r["server"] != server) or (run and r["run_id"] != run) \
                        or (provider and r["provider"] != provider):
                    continue
                rows.append(r)
    return rows


def cmd_summary(args):
    rows = load_rows(args.server, args.run, args.provider)
    if not rows:
        sys.exit("No target data found in %s" % bench.DATA)
    groups = defaultdict(list)
    for r in rows:
        groups[(r["server"], r["provider"])].append(r)
    for (server, prov), rs in sorted(groups.items()):
        runs = sorted(set(r["run_id"] for r in rs))
        report(rs, "Provider: %s | Server: %s | Runs: %d (%s .. %s) | Targets: Google search, Instagram"
               % (prov, server, len(runs), runs[0], runs[-1]))


def cmd_schedule(args):
    tag = "# mbench-targets"
    hours = [int(h) for h in args.hours.split(",")]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    now = datetime.datetime.now(datetime.timezone.utc)
    me = os.path.abspath(__file__)
    lines = []
    for d in range(args.start_in_days, args.start_in_days + args.days):
        day = today + datetime.timedelta(days=d)
        for h in hours:
            at_utc = datetime.datetime(day.year, day.month, day.day, h, args.minute,
                                       tzinfo=datetime.timezone.utc)
            if at_utc <= now:
                continue  # skip times that are already in the past
            at = at_utc.astimezone()
            lines.append("%d %d %d %d * cd %s && %s %s run --server %s >> %s 2>&1 %s" % (
                at.minute, at.hour, at.day, at.month, bench.HOME, sys.executable, me,
                args.server, os.path.join(bench.LOGS, "cron-targets.log"), tag))
    print("Target runs at %s UTC (minute %02d), starting %s:" % (
        ", ".join("%02d" % h for h in hours), args.minute,
        today + datetime.timedelta(days=args.start_in_days)))
    for ln in lines:
        print("  " + ln)
    if not args.install:
        print("\nNothing installed. Add --install to write these into cron.")
        return
    os.makedirs(bench.LOGS, exist_ok=True)
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    keep = [ln for ln in cur.stdout.splitlines() if tag not in ln] if cur.returncode == 0 else []
    subprocess.run(["crontab", "-"], input="\n".join(keep + lines) + "\n", text=True, check=True)
    print("\nInstalled %d target runs into cron. Check with:  crontab -l" % len(lines))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("run")
    s.add_argument("--server", required=True, help="label of this test server, e.g. de, us, sg")
    s.add_argument("--n-google", type=int, default=20, help="Google requests per provider and country")
    s.add_argument("--n-instagram", type=int, default=30, help="Instagram requests per provider and country")
    s.add_argument("--countries", default=",".join(bench.COUNTRIES))
    s.add_argument("--instagram-countries", default="us,de,gb")
    s.add_argument("--providers", default="")
    s.add_argument("--workers", type=int, default=5)
    s.add_argument("--timeout", type=float, default=40)
    s.add_argument("--run-id", default="")
    s.add_argument("--engine", choices=["phone", "urllib"], default="phone" if cffi_requests else "urllib",
                   help="phone = phone browser TLS fingerprint (curl_cffi); urllib = plain Python")
    s.add_argument("--google-url", default="", help="override (for tests only)")
    s.add_argument("--instagram-url", default="", help="override (for tests only)")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("summary")
    s.add_argument("--server", default="")
    s.add_argument("--run", default="")
    s.add_argument("--provider", default="")
    s.set_defaults(fn=cmd_summary)

    s = sub.add_parser("schedule")
    s.add_argument("--server", required=True)
    s.add_argument("--days", type=int, default=4)
    s.add_argument("--hours", default="11,23", help="UTC hours, comma separated")
    s.add_argument("--minute", type=int, default=0)
    s.add_argument("--start-in-days", type=int, default=0)
    s.add_argument("--install", action="store_true")
    s.set_defaults(fn=cmd_schedule)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
