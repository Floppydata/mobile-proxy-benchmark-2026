#!/usr/bin/env python3
"""IP quality of the exit IPs collected by the mobile benchmark.

Scamalytics (fraud score, datacenter/VPN/proxy flags) + IPinfo Lite (ASN, country), the same
sources as the residential benchmark. Mobile IP Share and Carrier Mix need a paid IP database;
that step is added when the database is bought.

  python3 ipquality.py setup                        (enter keys once, hidden; saved to keys.json)
  python3 ipquality.py run --per-provider 50        (pilot; later 300)
  python3 ipquality.py summary

IPs are read from data/infra_*.csv and data/remote/infra_*.csv (copies from the other servers).
The sample is spread evenly over the requested countries. Every answer is cached in ipcache.json,
so an IP is never looked up twice.
"""
import argparse, base64, csv, getpass, glob, json, os, random, statistics, sys, time
import urllib.error, urllib.parse, urllib.request
from collections import defaultdict

import bench

CONF = os.path.join(bench.HOME, "keys.json")
CACHE = os.path.join(bench.HOME, "ipcache.json")
SAMPLE = os.path.join(bench.HOME, "ipsample.csv")
RESULTS = os.path.join(bench.DATA, "ipquality.csv")
SCAM_BASE = os.environ.get("SCAM_BASE", "https://api11.scamalytics.com/v3")
IPINFO_BASE = os.environ.get("IPINFO_BASE", "https://api.ipinfo.io/lite")
IP2L_BASE = os.environ.get("IP2L_BASE", "https://api.ip2location.io")
IP2L_CACHE = os.path.join(bench.HOME, "ip2lcache.json")
IP2L_SAMPLE = os.path.join(bench.HOME, "ip2lsample.csv")
MM_BASE = os.environ.get("MM_BASE", "https://geoip.maxmind.com/geoip/v2.1/insights")
MM_CACHE = os.path.join(bench.HOME, "mmcache.json")
MM_SAMPLE = os.path.join(bench.HOME, "mmsample.csv")
HOSTING_WORDS = ("hosting", "cloud", "datacenter", "data center", "data-center", "server", "vps", "colo",
                 "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner",
                 "leaseweb", "m247", "cloudflare", "linode", "akamai", "vultr", "contabo", "choopa",
                 "oracle", "alibaba", "tencent", "scaleway", "packet", "datacamp", "cdn77", "zenlayer",
                 "ipxo", "psychz", "quadranet", "colocrossing", "serverius", "worldstream")


def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def save_json(path, obj, private=False):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)


def cmd_setup(args):
    c = load_json(CONF, {})
    c["scam_user"] = input("Scamalytics API username [%s]: " % ("saved" if c.get("scam_user") else "empty")).strip() \
        or c.get("scam_user", "")
    c["scam_key"] = getpass.getpass("Scamalytics API key (hidden): ").strip() or c.get("scam_key", "")
    c["ipinfo_token"] = getpass.getpass("IPinfo Lite token (hidden): ").strip() or c.get("ipinfo_token", "")
    c["ip2l_key"] = getpass.getpass("IP2Location.io API key (hidden, Enter keeps the saved one): ").strip() \
        or c.get("ip2l_key", "")
    c["mm_account"] = input("MaxMind account ID [%s]: " % ("saved" if c.get("mm_account") else "empty")).strip() \
        or c.get("mm_account", "")
    c["mm_key"] = getpass.getpass("MaxMind license key (hidden, Enter keeps the saved one): ").strip() \
        or c.get("mm_key", "")
    save_json(CONF, c, private=True)
    print("Saved to %s (readable only by you)." % CONF)


def cmd_set_maxmind(args):
    """MaxMind only, with visible input: some terminals do not paste into the hidden prompt."""
    c = load_json(CONF, {})
    c["mm_account"] = input("MaxMind account ID [%s]: " % (c.get("mm_account") or "empty")).strip() or c.get("mm_account", "")
    key = input("MaxMind license key (visible; paste and press Enter): ").strip()
    if key:
        c["mm_key"] = key
    save_json(CONF, c, private=True)
    print("Saved: account %s, license key %s. Clear the screen with:  clear" % (
        c.get("mm_account") or "-", "%d characters" % len(c.get("mm_key", "")) if c.get("mm_key") else "EMPTY"))


def http_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def lookup(ip, conf):
    out = {"ip": ip, "ts": bench.utcnow()}
    try:
        q = urllib.parse.urlencode({"key": conf["scam_key"], "ip": ip})
        res = http_json("%s/%s?%s" % (SCAM_BASE, urllib.parse.quote(conf["scam_user"]), q))
        out["scam"] = res.get("scamalytics", {})  # external_datasources are premium fields, not kept
    except Exception as e:  # noqa: BLE001
        out["scam_err"] = str(e)[:100]
    try:
        out["ipinfo"] = http_json("%s/%s?token=%s" % (IPINFO_BASE, urllib.parse.quote(ip), conf["ipinfo_token"]))
    except Exception as e:  # noqa: BLE001
        out["ipinfo_err"] = str(e)[:100]
    return out


def ip2l_lookup(ip, key):
    try:
        q = urllib.parse.urlencode({"key": key, "ip": ip, "format": "json"})
        return {"ip": ip, "ts": bench.utcnow(), "ip2l": http_json("%s/?%s" % (IP2L_BASE, q))}
    except urllib.error.HTTPError as e:
        return {"ip": ip, "ts": bench.utcnow(), "ip2l_err": "http_%d %s" % (e.code, e.read(200).decode(errors="replace"))}
    except Exception as e:  # noqa: BLE001
        return {"ip": ip, "ts": bench.utcnow(), "ip2l_err": str(e)[:100]}


def cmd_mobile(args):
    """Mobile IP Share and Carrier Mix: IP2Location.io usage_type and ASN on a large sample."""
    conf = load_json(CONF, {})
    if not conf.get("ip2l_key"):
        sys.exit("No IP2Location.io key saved. Run:  python3 ipquality.py setup")
    cache = load_json(IP2L_CACHE, {})
    rows = pick(collect(), args.per_provider, args.seed)
    new = sorted(set(ip for _, ip, _, _ in rows if ip not in cache))
    print("Mobile sample: %d IPs. New IP2Location.io lookups needed: %d." % (len(rows), len(new)))
    if len(new) > args.max_new:
        sys.exit("Too many new lookups (%d > --max-new %d)." % (len(new), args.max_new))
    if not args.yes and input("Continue? [y/N] ").strip().lower() != "y":
        return
    with open(IP2L_SAMPLE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["provider", "ip", "country_req", "server"])
        w.writerows(rows)
    fails = 0
    for n, ip in enumerate(new, 1):
        res = ip2l_lookup(ip, conf["ip2l_key"])
        cache[ip] = res
        err = res.get("ip2l_err", "")
        if err.startswith(("http_401", "http_403")) or "invalid" in err.lower():
            save_json(IP2L_CACHE, cache)
            sys.exit("IP2Location.io refused the key: %s" % err)
        fails = fails + 1 if err else 0
        if fails >= 20:
            save_json(IP2L_CACHE, cache)
            sys.exit("20 failed lookups in a row, stopped: %s" % err)
        if n % 500 == 0 or n == len(new):
            save_json(IP2L_CACHE, cache)
            print("[%d/%d] done" % (n, len(new)))
        time.sleep(args.sleep)
    save_json(IP2L_CACHE, cache)
    mobile_summary()


def mobile_summary():
    cache = load_json(IP2L_CACHE, {})
    by = defaultdict(list)
    with open(IP2L_SAMPLE, newline="") as f:
        for r in csv.DictReader(f):
            d = (cache.get(r["ip"]) or {}).get("ip2l")
            if d and "usage_type" in d:
                by[r["provider"]].append(dict(usage=d.get("usage_type") or "", asn=d.get("asn") or "", as_name=d.get("as") or "",
                                              cc=r["country_req"], v6=":" in r["ip"]))
    head = "%-12s| %-6s| %-24s| %-24s| %-24s| %s" % ("Provider", "IPs", "Mobile IP Share (95% CI)", "Mobile, IPv4 only",
                                                   "Mobile, IPv6 only", "Other usage types")
    print(head)
    print("-" * len(head))
    for prov in sorted(by):
        ds = by[prov]
        mob = [d for d in ds if "MOB" in d["usage"].split("/")]
        v4 = [d for d in ds if not d["v6"]]
        v6 = [d for d in ds if d["v6"]]
        other = defaultdict(int)
        for d in ds:
            if d not in mob:
                other[d["usage"] or "?"] += 1
        print("%-12s| %-6d| %-24s| %-24s| %-24s| %s" % (
            bench.PROVIDERS.get(prov, {}).get("label", prov), len(ds), bench.fmt_rate(len(mob), len(ds)),
            bench.fmt_rate(sum(d in mob for d in v4), len(v4)), bench.fmt_rate(sum(d in mob for d in v6), len(v6)),
            ", ".join("%s %d" % kv for kv in sorted(other.items(), key=lambda kv: -kv[1])[:3])))


def mm_lookup(ip, account, key):
    req = urllib.request.Request("%s/%s" % (MM_BASE, urllib.parse.quote(ip)),
                                 headers={"Authorization": "Basic " + base64.b64encode(
                                     ("%s:%s" % (account, key)).encode()).decode(), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return {"ip": ip, "ts": bench.utcnow(), "mm": json.loads(r.read().decode("utf-8", "replace"))}
    except urllib.error.HTTPError as e:
        return {"ip": ip, "ts": bench.utcnow(), "mm_err": "http_%d %s" % (e.code, e.read(200).decode(errors="replace"))}
    except Exception as e:  # noqa: BLE001
        return {"ip": ip, "ts": bench.utcnow(), "mm_err": str(e)[:100]}


def cmd_maxmind(args):
    """Cross-check of Mobile IP Share: MaxMind GeoIP Insights traits.user_type / connection_type."""
    conf = load_json(CONF, {})
    if not (conf.get("mm_account") and conf.get("mm_key")):
        sys.exit("No MaxMind account ID / license key saved. Run:  python3 ipquality.py setup")
    cache = load_json(MM_CACHE, {})
    if os.path.exists(IP2L_SAMPLE):
        # the IP2Location sample is ordered round-robin over countries: its first N per provider are a balanced subsample
        per = defaultdict(list)
        with open(IP2L_SAMPLE, newline="") as f:
            for r in csv.DictReader(f):
                if len(per[r["provider"]]) < args.per_provider:
                    per[r["provider"]].append((r["provider"], r["ip"], r["country_req"], r["server"]))
        rows = [x for p in sorted(per) for x in per[p]]
    else:
        rows = pick(collect(), args.per_provider, args.seed)
    new = sorted(set(ip for _, ip, _, _ in rows if ip not in cache))
    print("MaxMind sample: %d IPs. New Insights lookups needed: %d ($0.002 each = about $%.0f)." % (
        len(rows), len(new), len(new) * 0.002))
    if len(new) > args.max_new:
        sys.exit("Too many new lookups (%d > --max-new %d)." % (len(new), args.max_new))
    if not args.yes and input("Continue? [y/N] ").strip().lower() != "y":
        return
    with open(MM_SAMPLE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["provider", "ip", "country_req", "server"])
        w.writerows(rows)
    left = None
    for n, ip in enumerate(new, 1):
        res = mm_lookup(ip, conf["mm_account"], conf["mm_key"])
        cache[ip] = res
        err = res.get("mm_err", "")
        if err.startswith(("http_401", "http_402", "http_403")):
            save_json(MM_CACHE, cache)
            sys.exit("MaxMind refused the request: %s" % err)
        left = ((res.get("mm") or {}).get("maxmind") or {}).get("queries_remaining", left)
        if n % 250 == 0 or n == len(new):
            save_json(MM_CACHE, cache)
            print("[%d/%d] done%s" % (n, len(new), ("  queries remaining: %s" % left) if left is not None else ""))
        time.sleep(args.sleep)
    save_json(MM_CACHE, cache)
    maxmind_summary()


def maxmind_summary():
    cache = load_json(MM_CACHE, {})
    ip2l = load_json(IP2L_CACHE, {})
    by = defaultdict(list)
    with open(MM_SAMPLE, newline="") as f:
        for r in csv.DictReader(f):
            t = ((cache.get(r["ip"]) or {}).get("mm") or {}).get("traits")
            if t is None:
                continue
            u = ((ip2l.get(r["ip"]) or {}).get("ip2l") or {}).get("usage_type", "")
            by[r["provider"]].append(dict(cell=t.get("user_type") == "cellular" or t.get("connection_type") == "Cellular",
                                          mnc=bool(t.get("mobile_network_code")), user_type=t.get("user_type", "?"),
                                          ip2l=u))
    head = "%-12s| %-6s| %-24s| %-14s| %-30s| %s" % ("Provider", "IPs", "Cellular (95% CI)", "Has MCC/MNC",
                                                   "Agreement with IP2Location MOB", "Top other user types")
    print(head)
    print("-" * len(head))
    for prov in sorted(by):
        ds = by[prov]
        both = [d for d in ds if d["ip2l"]]
        agree = sum(1 for d in both if d["cell"] == ("MOB" in d["ip2l"].split("/")))
        other = defaultdict(int)
        for d in ds:
            if not d["cell"]:
                other[d["user_type"]] += 1
        print("%-12s| %-6d| %-24s| %-14s| %-30s| %s" % (
            bench.PROVIDERS.get(prov, {}).get("label", prov), len(ds), bench.fmt_rate(sum(d["cell"] for d in ds), len(ds)),
            "%.0f%%" % (100.0 * sum(d["mnc"] for d in ds) / len(ds)),
            ("%.0f%% of %d" % (100.0 * agree / len(both), len(both))) if both else "-",
            ", ".join("%s %d" % kv for kv in sorted(other.items(), key=lambda kv: -kv[1])[:3])))


def collect():
    """provider -> country -> {ip: server} from all successful infrastructure requests."""
    by = defaultdict(lambda: defaultdict(dict))
    files = glob.glob(os.path.join(bench.DATA, "infra_*.csv")) + glob.glob(os.path.join(bench.DATA, "remote", "infra_*.csv"))
    for fn in sorted(files):
        with open(fn, newline="") as f:
            for r in csv.DictReader(f):
                if r["ok"] == "1" and r["ip"]:
                    by[r["provider"]][r["country_req"]].setdefault(r["ip"], r["server"])
    return by


def pick(by, per_provider, seed):
    """Round-robin over countries, so every country gets the same share of the sample."""
    rnd = random.Random(seed)
    rows = []
    for prov in sorted(by):
        per_cc = {}
        for cc, ips in by[prov].items():
            lst = sorted(ips)
            rnd.shuffle(lst)
            per_cc[cc] = lst
        picked, i = [], 0
        while len(picked) < per_provider and any(i < len(v) for v in per_cc.values()):
            for cc in sorted(per_cc):
                if i < len(per_cc[cc]) and len(picked) < per_provider:
                    ip = per_cc[cc][i]
                    picked.append((prov, ip, cc, by[prov][cc][ip]))
            i += 1
        rows += picked
    return rows


def cmd_run(args):
    conf = load_json(CONF, {})
    if not (conf.get("scam_user") and conf.get("scam_key") and conf.get("ipinfo_token")):
        sys.exit("Run 'setup' first.")
    cache = load_json(CACHE, {})
    by = collect()
    rows = pick(by, args.per_provider, args.seed)
    new = sorted(set(ip for _, ip, _, _ in rows if ip not in cache))
    print("Sample: %d IPs (%d providers, %s unique IPs seen in total). New lookups needed: %d." % (
        len(rows), len(by), sum(len(v) for p in by.values() for v in p.values()), len(new)))
    if len(new) > args.max_new:
        sys.exit("Too many new lookups (%d > --max-new %d)." % (len(new), args.max_new))
    if not args.yes and input("Continue? [y/N] ").strip().lower() != "y":
        return
    with open(SAMPLE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["provider", "ip", "country_req", "server"])
        w.writerows(rows)
    left = None
    for n, ip in enumerate(new, 1):
        res = lookup(ip, conf)
        cache[ip] = res
        left = (res.get("scam") or {}).get("credits", {}).get("remaining", left)
        if "scam_err" in res and ("401" in res["scam_err"] or "403" in res["scam_err"]):
            save_json(CACHE, cache)
            sys.exit("Scamalytics refused the key: %s" % res["scam_err"])
        if n % 50 == 0 or n == len(new):
            save_json(CACHE, cache)
            print("[%d/%d] done%s" % (n, len(new), ("  Scamalytics credits remaining: %s" % left) if left is not None else ""))
        time.sleep(0.15)
    save_json(CACHE, cache)
    print("Finished. Now run:  python3 ipquality.py summary")


def parse(res, cc):
    sc = res.get("scam") or {}
    px = sc.get("scamalytics_proxy") or {}
    info = res.get("ipinfo") or {}
    asname = (info.get("as_name") or "").lower()
    d = dict(ok=sc.get("scamalytics_score") is not None,
             score=sc.get("scamalytics_score"), risk=sc.get("scamalytics_risk"),
             dc=bool(px.get("is_datacenter")), vpn=bool(px.get("is_vpn")), resproxy=bool(px.get("is_resproxy")),
             other=bool(px.get("is_amazon_aws") or px.get("is_google") or px.get("is_apple_icloud_private_relay")),
             blacklisted=bool(sc.get("is_blacklisted_external")),
             host_asn=any(w in asname for w in HOSTING_WORDS), asn=info.get("asn", ""), as_name=info.get("as_name", ""),
             ipinfo_ok=bool(info.get("country_code")), geo=(info.get("country_code") or "").lower() == cc,
             v6=":" in res["ip"])
    d["proxy"] = d["dc"] or d["vpn"] or d["resproxy"] or d["other"]
    return d


def pct(k, n):
    return "%.1f%%" % (100.0 * k / n) if n else "-"


def cmd_summary(args):
    cache = load_json(CACHE, {})
    by = defaultdict(list)
    out = []
    with open(SAMPLE, newline="") as f:
        for r in csv.DictReader(f):
            if r["ip"] in cache:
                d = parse(cache[r["ip"]], r["country_req"])
                by[r["provider"]].append(d)
                out.append(dict(provider=r["provider"], country_req=r["country_req"], server=r["server"], ip=r["ip"],
                                **{k: d[k] for k in ("score", "risk", "proxy", "dc", "vpn", "resproxy", "blacklisted",
                                                     "asn", "as_name", "geo", "v6")}))
    os.makedirs(bench.DATA, exist_ok=True)
    with open(RESULTS, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]) if out else ["provider"])
        w.writeheader()
        w.writerows(out)
    head = "%-12s| %-5s| %-5s| %-10s| %-10s| %-22s| %-12s| %-10s| %-8s| %-9s| %-12s| %s" % (
        "Provider", "IPs", "IPv6", "Score avg", "Score med", "High risk (95% CI)", "Proxy Det.", "Datacenter",
        "VPN", "Host ASN", "Geo (IPinfo)", "Top ASNs")
    print(head)
    print("-" * len(head))
    for prov in sorted(by):
        ds = [d for d in by[prov] if d["ok"]]
        n = len(ds)
        if not n:
            print("%-12s| no valid Scamalytics answers" % prov)
            continue
        sc = [d["score"] for d in ds]
        hi = sum(1 for d in ds if d["risk"] in ("high", "very high"))
        gi = [d for d in by[prov] if d["ipinfo_ok"]]
        top = defaultdict(int)
        for d in by[prov]:
            top[d["as_name"] or "?"] += 1
        tops = ", ".join("%s %d" % (k[:18], v) for k, v in sorted(top.items(), key=lambda kv: -kv[1])[:2])
        print("%-12s| %-5d| %-5s| %-10.1f| %-10.1f| %-22s| %-12s| %-10s| %-8s| %-9s| %-12s| %s" % (
            bench.PROVIDERS.get(prov, {}).get("label", prov), n, pct(sum(d["v6"] for d in ds), n),
            statistics.mean(sc), statistics.median(sc), bench.fmt_rate(hi, n),
            pct(sum(d["proxy"] for d in ds), n), pct(sum(d["dc"] for d in ds), n),
            pct(sum(d["vpn"] for d in ds), n), pct(sum(d["host_asn"] for d in by[prov]), len(by[prov])),
            pct(sum(d["geo"] for d in gi), len(gi)), tops))
    print("\nPer-IP results saved to %s" % RESULTS)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").set_defaults(f=cmd_setup)
    sub.add_parser("set-maxmind", help="enter the MaxMind account ID and license key (visible input)").set_defaults(f=cmd_set_maxmind)
    r = sub.add_parser("run")
    r.add_argument("--per-provider", type=int, default=50)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--max-new", type=int, default=4000)
    r.add_argument("--yes", action="store_true")
    r.set_defaults(f=cmd_run)
    sub.add_parser("summary").set_defaults(f=cmd_summary)
    m = sub.add_parser("mobile", help="Mobile IP Share and Carrier Mix with IP2Location.io")
    m.add_argument("--per-provider", type=int, default=10000)
    m.add_argument("--seed", type=int, default=1)
    m.add_argument("--max-new", type=int, default=140000)
    m.add_argument("--sleep", type=float, default=0.02)
    m.add_argument("--yes", action="store_true")
    m.set_defaults(f=cmd_mobile)
    sub.add_parser("mobile-summary").set_defaults(f=lambda a: mobile_summary())
    mm = sub.add_parser("maxmind", help="cross-check with MaxMind GeoIP Insights (paid per query)")
    mm.add_argument("--per-provider", type=int, default=1000)
    mm.add_argument("--seed", type=int, default=2)
    mm.add_argument("--max-new", type=int, default=12000)
    mm.add_argument("--sleep", type=float, default=0.05)
    mm.add_argument("--yes", action="store_true")
    mm.set_defaults(f=cmd_maxmind)
    sub.add_parser("maxmind-summary").set_defaults(f=lambda a: maxmind_summary())
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
