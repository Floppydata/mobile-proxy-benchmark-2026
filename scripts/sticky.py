#!/usr/bin/env python3
"""Sticky session test for mobile proxies: how long a sticky IP really lives.

Needs bench.py, providers.json and format_choice.json (from 'bench.py check') in the same folder.

  python3 sticky.py run      --server us          (30-minute test: 8 sessions per provider)
  python3 sticky.py summary                       (IP lifetime table)
  python3 sticky.py schedule --server us --until "2026-11-10 22:00" --install

Every session asks for a 30-minute sticky IP and checks it every 30 seconds.
The IP lifetime of a session ends at the first answer with another IP, or at the
first of 3 failed checks in a row (the device went offline). Sessions that keep
their IP to the end are counted as surviving 30 minutes.
"""
import argparse, csv, os, random, statistics, subprocess, sys, threading, time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import bench

FIELDS = ["run_id", "ts_utc", "server", "provider", "fmt", "session", "country", "t_sec", "ok", "ip", "err"]
DROP_AFTER = 3  # failed checks in a row that end the IP lifetime
# Port-based sticky formats (Decodo, DataImpulse) use one port per session. Each server
# gets its own block of ports so that sessions of parallel servers never share a port.
SERVER_SLOT = {"us": 0, "de": 1, "sg": 2}


def now():
    return datetime.now(timezone.utc)


def fetch_ip(opener, target, timeout=25):
    """Returns (ip, err)."""
    try:
        d, _n = bench.trace(opener, target, timeout)
        return (d["ip"], "") if d.get("ip") else ("", "no_ip_in_reply")
    except Exception as e:  # noqa: BLE001
        return "", bench.classify_error(e)


# -------------------------------------------------------------------- run
lock = threading.Lock()


def session_worker(cred, key, fmt_i, run_id, server, idx, cc, ses, minutes, interval, writer, target):
    fmt = bench.PROVIDERS[key]["sticky"][fmt_i]
    opener = bench.opener_for(bench.proxy_url(cred, fmt, cc, ses, minutes))
    start = time.time()
    end = start + minutes * 60
    k = 0
    while True:
        t = time.time() - start
        ip, err = fetch_ip(opener, target)
        with lock:
            writer.writerow(dict(run_id=run_id, ts_utc=now().strftime("%Y-%m-%dT%H:%M:%SZ"), server=server,
                                 provider=key, fmt=fmt_i + 1, session=idx, country=cc, t_sec=int(t),
                                 ok=int(bool(ip)), ip=ip, err=err))
        k += 1
        nxt = start + k * interval
        if nxt > end:
            break
        time.sleep(max(0, nxt - time.time()))


def cmd_run(args):
    cfg = bench.load_config()["providers"]
    choice = bench.load_choice()["sticky"]
    if not choice:
        sys.exit("No sticky formats saved. Run:  python3 bench.py check")
    run_id = args.run_id or now().strftime("%Y%m%d-%H%M")
    os.makedirs(bench.DATA, exist_ok=True)
    path = os.path.join(bench.DATA, "sticky_%s_%s.csv" % (args.server, run_id))
    rnd = random.Random(run_id + args.server)
    countries = [rnd.choice(bench.COUNTRIES) for _ in range(args.sessions)]
    slot = SERVER_SLOT.get(args.server, 3) * 20
    jobs = []
    for key, cred in cfg.items():
        if key not in choice or (args.providers and key not in args.providers):
            continue
        for i in range(args.sessions):
            jobs.append((cred, key, choice[key], run_id, args.server, i + 1, countries[i],
                         bench.new_session(idx=slot + i), args.minutes, args.interval))
    print("Sticky run %s on %s: %d sessions, %d min, check every %d s" %
          (run_id, args.server, len(jobs), args.minutes, args.interval))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futs = []
            for j in jobs:
                futs.append(ex.submit(session_worker, *j, w, args.target))
                time.sleep(0.2)
            for fu in futs:
                fu.result()
    print("Saved %s" % path)


# ---------------------------------------------------------------- summary
def load_rows(server=None):
    rows = []
    if not os.path.isdir(bench.DATA):
        return rows
    for fn in sorted(os.listdir(bench.DATA)):
        if fn.startswith("sticky_") and fn.endswith(".csv"):
            if server and ("_%s_" % server) not in fn:
                continue
            with open(os.path.join(bench.DATA, fn)) as f:
                rows += list(csv.DictReader(f))
    return rows


def lifetime(rs, minutes):
    """IP lifetime of one session in minutes and whether it survived the whole window."""
    rs = sorted(rs, key=lambda r: int(r["t_sec"]))
    first, fails, fail_start = None, 0, None
    for r in rs:
        t = int(r["t_sec"]) / 60.0
        if r["ok"] == "1":
            if first is None:
                first = r["ip"]
            elif r["ip"] != first:
                # a new IP at or after the requested length is the provider keeping its promise
                return (float(minutes), True) if t >= minutes else (t, False)
            fails, fail_start = 0, None
        elif first is not None:
            fails += 1
            fail_start = t if fail_start is None else fail_start
            if fails >= DROP_AFTER:
                return fail_start, False
    if first is None:
        return None, False  # the session never answered
    return float(minutes), True


def analyse(rows, minutes):
    by = defaultdict(list)
    for r in rows:
        by[(r["run_id"], r["server"], r["provider"], r["session"])].append(r)
    out = defaultdict(list)
    for (_run, _srv, prov, _ses), rs in by.items():
        life, full = lifetime(rs, minutes)
        out[prov].append(dict(started=life is not None, life=life or 0.0, full=full,
                              n=len(rs), ok=sum(1 for r in rs if r["ok"] == "1")))
    return out


def cmd_summary(args):
    rows = load_rows(args.server)
    if not rows:
        sys.exit("No sticky data yet.")
    res = analyse(rows, args.minutes)
    head = "%-12s| %-9s| %-9s| %-20s| %-26s| %-26s| %s" % (
        "Provider", "Sessions", "Started", "Median IP life, min", "Lived >= 10 min (95% CI)",
        "Lived %d min (95%% CI)" % args.minutes, "Check error rate")
    print(head)
    print("-" * len(head))
    for prov in sorted(res, key=lambda p: -statistics.median(s["life"] for s in res[p])):
        ss = res[prov]
        n = len(ss)
        started = [s for s in ss if s["started"]]
        med = statistics.median(s["life"] for s in ss)
        k10 = sum(1 for s in ss if s["life"] >= 10)
        kfull = sum(1 for s in ss if s["full"])
        okreq, allreq = sum(s["ok"] for s in ss), sum(s["n"] for s in ss)
        print("%-12s| %-9d| %-9d| %-20.1f| %-26s| %-26s| %.1f%%" % (
            bench.PROVIDERS.get(prov, {}).get("label", prov), n, len(started), med,
            bench.fmt_rate(k10, n), bench.fmt_rate(kfull, n), (allreq - okreq) / allreq * 100))
    print("\nSessions that never answered count as 0 minutes. Lifetime ends at an IP change "
          "or at %d failed checks in a row." % DROP_AFTER)


# --------------------------------------------------------------- schedule
def cmd_schedule(args):
    start = now() + timedelta(minutes=5)
    if args.start_in_days:
        start = (now() + timedelta(days=args.start_in_days)).replace(hour=0, minute=0, second=0, microsecond=0)
    until = datetime.strptime(args.until, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
    hours = [int(h) for h in args.hours.split(",")]
    runs, d = [], start.replace(hour=0, minute=0, second=0, microsecond=0)
    while d <= until:
        for h in hours:
            t = d.replace(hour=h, minute=args.minute)
            if start <= t <= until:
                runs.append(t.astimezone())
        d += timedelta(days=1)
    here = os.path.dirname(os.path.abspath(__file__))
    lines = ["%d %d %d %d * cd %s && %s %s run --server %s >> %s/logs/cron-sticky.log 2>&1 # mbench-sticky" %
             (t.minute, t.hour, t.day, t.month, here, sys.executable, os.path.join(here, "sticky.py"),
              args.server, here) for t in runs]
    print("Sticky runs, %d min each (times in server local time):" % bench.STICKY_MIN)
    for ln in lines:
        print("  " + ln)
    if not args.install:
        print("\nNothing installed. Add --install to put them into cron.")
        return
    os.makedirs(os.path.join(here, "logs"), exist_ok=True)
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    keep = [ln for ln in cur.splitlines() if "# mbench-sticky" not in ln]
    subprocess.run(["crontab", "-"], input="\n".join(keep + lines) + "\n", text=True, check=True)
    print("\nInstalled %d sticky runs into cron. Check with:  crontab -l" % len(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--server", required=True)
    r.add_argument("--sessions", type=int, default=8)
    r.add_argument("--minutes", type=int, default=bench.STICKY_MIN)
    r.add_argument("--interval", type=int, default=30)
    r.add_argument("--providers", nargs="*")
    r.add_argument("--run-id")
    r.add_argument("--target", default=bench.DEFAULT_TARGET)
    r.set_defaults(f=cmd_run)
    s = sub.add_parser("summary")
    s.add_argument("--server")
    s.add_argument("--minutes", type=int, default=bench.STICKY_MIN)
    s.set_defaults(f=cmd_summary)
    sc = sub.add_parser("schedule")
    sc.add_argument("--server", required=True)
    sc.add_argument("--until", required=True, help='UTC, e.g. "2026-11-10 22:00"')
    sc.add_argument("--hours", default="3,9,15,21", help="UTC hours")
    sc.add_argument("--minute", type=int, default=30)
    sc.add_argument("--start-in-days", type=int, default=0, help="first run on that day (UTC midnight)")
    sc.add_argument("--install", action="store_true")
    sc.set_defaults(f=cmd_schedule)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
