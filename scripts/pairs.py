#!/usr/bin/env python3
"""Mobile proxy benchmark - 95% confidence intervals of pairwise differences.

The workbook gives Wilson intervals for rates (Success Rate, Geo Accuracy, sticky shares, ...),
and a tie is called when two such intervals overlap. Latency, Duplicate Rate and the median sticky
IP lifetime have no interval there, so this script computes one for the difference between two
providers from the raw logs:

  latency, latency-p90  median / P90 of request time on successful infrastructure requests,
                        pooled over all runs as in the workbook; bootstrap that resamples whole
                        runs (server x run_id), because requests inside one run are not independent.
  duplicate             1 - unique IPs / successful requests over the whole test, as in the workbook;
                        delete-one-run jackknife of the difference (a bootstrap would repeat runs and
                        so invent duplicates), in percentage points.
  duplicate-run         the same per run (about 1,200 requests in a few minutes), paired by run;
                        bootstrap of the mean per-run difference. For reference.
  latency-sg            median request time from the Singapore server only, bootstrap over runs.
  sticky-life           median sticky IP lifetime in minutes (rule of sticky.py), bootstrap over
                        sessions.

A difference whose interval contains 0 is a tie. Same method and seed as the residential pairs.py.

Only the Python standard library is used. Example:

  python3 scripts/pairs.py --raw RAW --out pairs.json          # Floppydata against each other provider
  python3 scripts/pairs.py --raw RAW --all --out pairs.json    # every pair
"""
import argparse
import csv
import glob
import json
import os
import random
import statistics
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sticky  # noqa: E402

START = "2026-10-24 00:00:00"
PROVIDERS = ["Floppydata", "Decodo", "Oxylabs", "Evomi", "SOAX", "DataImpulse", "ProxyEmpire", "NodeMaven",
             "IPRoyal", "Byteful", "ResiProx"]
OWN = "Floppydata"
METRICS = ("latency", "latency-p90", "duplicate", "duplicate-run", "latency-sg", "sticky-life")


def files(raw, prefix):
    """RAW/<server>/<prefix>_*.csv or RAW/<server>/data/<prefix>_*.csv."""
    return sorted(glob.glob(os.path.join(raw, "*", prefix + "_*.csv")) +
                  glob.glob(os.path.join(raw, "*", "data", prefix + "_*.csv")))


def ts_ok(r):
    return r["ts_utc"].replace("T", " ").replace("Z", "") >= START


def load(raw):
    """provider -> run (server/run_id) -> list of (sec, ip) of successful requests; and the same from sg."""
    runs = defaultdict(lambda: defaultdict(list))
    sg = defaultdict(lambda: defaultdict(list))
    for path in files(raw, "infra"):
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                if r["ok"] == "1" and ts_ok(r):
                    runs[r["provider"]][r["server"] + "/" + r["run_id"]].append((float(r["sec"]), r["ip"]))
                    if r["server"] == "sg":
                        sg[r["provider"]][r["run_id"]].append(float(r["sec"]))
    return runs, sg


def load_sticky(raw):
    """provider -> list of session lifetimes, minutes."""
    by = defaultdict(list)
    for path in files(raw, "sticky"):
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                if ts_ok(r):
                    by[(r["provider"], r["server"], r["run_id"], r["session"])].append(r)
    out = defaultdict(list)
    for (prov, _s, _r, _ses), rs in by.items():
        life, _full = sticky.lifetime(rs, sticky.bench.STICKY_MIN)
        out[prov].append(life or 0.0)
    return out


def ci(d, reps):
    d.sort()
    return [round(d[int(0.025 * reps)], 4), round(d[int(0.975 * reps) - 1], 4)]


def median_p90(values):
    s = sorted(values)
    return statistics.median(s), s[int(0.9 * (len(s) - 1))]


def dup(rows):
    return 1 - len(set(ip for _, ip in rows)) / len(rows)


def dup_leave_one_out(runs, keys):
    """Whole-test Duplicate Rate with each run left out in turn, and with nothing left out."""
    per = {k: Counter(ip for _, ip in runs[k]) for k in keys}
    total = Counter()
    for c in per.values():
        total.update(c)
    n, u = sum(total.values()), len(total)
    out = []
    for k in keys:
        lost = sum(1 for ip, m in per[k].items() if total[ip] == m)  # IPs seen only in this run
        out.append(1 - (u - lost) / (n - sum(per[k].values())))
    return 1 - u / n, out


def jackknife_diff(runs_a, runs_b, keys):
    full_a, loo_a = dup_leave_one_out(runs_a, keys)
    full_b, loo_b = dup_leave_one_out(runs_b, keys)
    d = [100 * (a - b) for a, b in zip(loo_a, loo_b)]
    m, k = statistics.mean(d), len(d)
    se = ((k - 1) / k * sum((x - m) ** 2 for x in d)) ** 0.5
    est = 100 * (full_a - full_b)
    return [round(est - 1.96 * se, 4), round(est + 1.96 * se, 4)]


def pair(runs, sg, life, a, b, reps, rng, rng_extra):
    ra, rb = runs[a.lower()], runs[b.lower()]
    ca, cb = list(ra.values()), list(rb.values())
    lat_d, p90_d = [], []
    for _ in range(reps):
        ma, pa = median_p90([s for c in rng.choices(ca, k=len(ca)) for s, _ in c])
        mb, pb = median_p90([s for c in rng.choices(cb, k=len(cb)) for s, _ in c])
        lat_d.append(ma - mb)
        p90_d.append(pa - pb)
    shared = sorted(set(ra) & set(rb))
    per_run = [100 * (dup(ra[k]) - dup(rb[k])) for k in shared]
    dup_d = [statistics.mean(rng.choices(per_run, k=len(per_run))) for _ in range(reps)]
    out = {"latency": ci(lat_d, reps), "latency-p90": ci(p90_d, reps), "duplicate": jackknife_diff(ra, rb, shared),
           "duplicate-run": ci(dup_d, reps), "runs": len(shared)}

    sa, sb = list(sg[a.lower()].values()), list(sg[b.lower()].values())
    d = []
    for _ in range(reps):
        d.append(statistics.median([v for c in rng_extra.choices(sa, k=len(sa)) for v in c]) -
                 statistics.median([v for c in rng_extra.choices(sb, k=len(sb)) for v in c]))
    out["latency-sg"] = ci(d, reps)
    la, lb = life[a.lower()], life[b.lower()]
    d = [statistics.median(rng_extra.choices(la, k=len(la))) - statistics.median(rng_extra.choices(lb, k=len(lb)))
         for _ in range(reps)]
    out["sticky-life"] = ci(d, reps)
    out["sessions"] = [len(la), len(lb)]
    return out


def verdict(iv, lower_is_better=True):
    lo, hi = iv
    if lo <= 0 <= hi:
        return "tie"
    first_lower = hi < 0
    return "first better" if first_lower == lower_is_better else "second better"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", required=True, help="folder with us/, de/, sg/ (each with infra_*.csv or data/infra_*.csv)")
    ap.add_argument("--all", action="store_true", help="every pair, not only Floppydata against the others")
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="", help="write JSON here")
    args = ap.parse_args()

    runs, sg = load(args.raw)
    life = load_sticky(args.raw)
    rng, rng_extra = random.Random(args.seed), random.Random(args.seed + 1)
    present = [p for p in PROVIDERS if runs.get(p.lower())]
    if args.all:
        pairs = [(a, b) for i, a in enumerate(present) for b in present[i + 1:]]
    else:
        pairs = [(OWN, b) for b in present if b != OWN]
    result = {}
    for a, b in pairs:
        r = pair(runs, sg, life, a, b, args.reps, rng, rng_extra)
        result["%s|%s" % (a, b)] = r
        print("%-26s latency %-18s p90 %-18s dup %-18s sg %-18s sticky-life %s" % (
            a + " vs " + b, r["latency"], r["latency-p90"], r["duplicate"], r["latency-sg"], r["sticky-life"]))
        print("%-26s -> latency %s, p90 %s, duplicate %s, latency-sg %s, sticky-life %s" % (
            "", verdict(r["latency"]), verdict(r["latency-p90"]), verdict(r["duplicate"]), verdict(r["latency-sg"]),
            verdict(r["sticky-life"], lower_is_better=False)))
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"seed": args.seed, "reps": args.reps, "start": START,
                       "note": "95% interval of 'first minus second': seconds for latency, percentage points for "
                               "duplicate, minutes for sticky-life; an interval containing 0 is a tie",
                       "pairs": result}, f, indent=1)


if __name__ == "__main__":
    main()
