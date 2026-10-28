#!/usr/bin/env python3
"""Build the public copy of the mobile benchmark (the GitHub repository) from the raw server data.

  python3 -I scripts/release.py --raw RAW --ipq IPQ --results results/results.xlsx --pairs results/pairs.json \
      --counters results/counters.csv --out release

RAW has one folder per server (us, de, sg), each with the server's data/ folder; IPQ holds ipsample.csv,
ipcache.json, ip2lsample.csv, ip2lcache.json, mmsample.csv and mmcache.json from the IP-quality server.

What it does:
  1. copies every raw CSV to OUT/data/raw/<server>/ with each exit IP replaced by `ip_` + 16 hex characters:
     HMAC-SHA256 with a random key that is used once and never saved. The same address gets the same value
     in every file, so unique-IP counts, Duplicate Rate and sticky IP changes stay as they are;
  2. writes per-provider aggregates of the IP databases (no addresses, no raw answers);
  3. copies the scripts, the results workbook, pairs.json, README and licences;
  4. scans OUT for anything that must not be published (IP addresses, server names, credentials, tokens)
     and exits with an error if it finds one.

Only the Python standard library is used.
"""
import argparse, csv, glob, hashlib, hmac, ipaddress, json, os, re, secrets, shutil, sys, zipfile
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import ipquality  # noqa: E402

SERVERS = ["us", "de", "sg"]
PUBLIC_SCRIPTS = ["bench.py", "targets.py", "sticky.py", "fingerprint.py", "ipquality.py", "analyze.py", "pairs.py",
                  "release.py", "site_data.py"]
IP_RE = re.compile(r"(?<![\w.:/])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
# never published: our servers, the endpoint, private files and words that mark credentials
FORBIDDEN = [r"your-server\.de", r"[\"']password[\"']\s*:\s*[\"'][^\"'{]{6,}[\"']", r"\bkey=[A-Za-z0-9_-]{16,}",
             r"\bBEGIN (?:RSA |EC )?PRIVATE KEY"]
# Logins, keys and server addresses are also looked for literally: pass a private file with one string per line
# (--secrets; it is never part of the release).


def hasher():
    key = secrets.token_bytes(32)
    cache = {}

    def h(ip):
        if not ip or ip.startswith("ip_"):
            return ip
        if ip not in cache:
            cache[ip] = "ip_" + hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:16]
        return cache[ip]
    return h


def anonymize(raw, out, h):
    n_files = n_rows = 0
    for srv in SERVERS:
        dst = os.path.join(out, "data", "raw", srv)
        os.makedirs(dst, exist_ok=True)
        for fn in sorted(glob.glob(os.path.join(raw, srv, "data", "*.csv"))):
            name = os.path.basename(fn)
            if name.startswith("ipquality"):
                continue  # per-IP database answers stay private
            with open(fn, newline="") as f:
                rows = list(csv.DictReader(f))
                fields = rows[0].keys() if rows else []
            with open(os.path.join(dst, name), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(fields))
                w.writeheader()
                for r in rows:
                    if "ip" in r:
                        r["ip"] = h(r["ip"])
                    w.writerow(r)
            n_files += 1
            n_rows += len(rows)
    return n_files, n_rows


def aggregates(ipq, out):
    """Per-provider tables of the IP databases; nothing per IP."""
    d = os.path.join(out, "data")
    written = []
    sample, cache_p = os.path.join(ipq, "ipsample.csv"), os.path.join(ipq, "ipcache.json")
    if os.path.exists(sample) and os.path.exists(cache_p):
        cache = json.load(open(cache_p))
        by = defaultdict(list)
        for r in csv.DictReader(open(sample, newline="")):
            if r["ip"] in cache:
                by[r["provider"]].append(ipquality.parse(cache[r["ip"]], r["country_req"]))
        with open(os.path.join(d, "ip_quality_aggregated.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Provider", "IPs checked", "Fraud Score avg (0-100)", "Fraud Score median", "High risk share",
                        "Proxy flags", "Datacenter", "VPN", "Hosting ASN (name heuristic)", "Geo accuracy (IPinfo)", "IPv6 share"])
            for p, ds in sorted(by.items()):
                v = [x for x in ds if x["ok"]]
                gi = [x for x in ds if x["ipinfo_ok"]]
                if not v:
                    continue
                n = len(v)
                w.writerow([p, n, round(sum(x["score"] for x in v) / n, 3), sorted(x["score"] for x in v)[n // 2],
                            round(sum(x["risk"] in ("high", "very high") for x in v) / n, 4),
                            round(sum(x["proxy"] for x in v) / n, 4), round(sum(x["dc"] for x in v) / n, 4),
                            round(sum(x["vpn"] for x in v) / n, 4), round(sum(x["host_asn"] for x in ds) / len(ds), 4),
                            round(sum(x["geo"] for x in gi) / len(gi), 4) if gi else "", round(sum(x["v6"] for x in ds) / len(ds), 4)])
        written.append("ip_quality_aggregated.csv")
    for prefix, kind in (("ip2l", "ip2l"), ("mm", "mm")):
        sample, cache_p = os.path.join(ipq, prefix + "sample.csv"), os.path.join(ipq, prefix + "cache.json")
        if not (os.path.exists(sample) and os.path.exists(cache_p)):
            continue
        cache = json.load(open(cache_p))
        cls = defaultdict(Counter)       # (provider, country) -> class counts
        carriers = defaultdict(Counter)  # (provider, country) -> network name counts
        for r in csv.DictReader(open(sample, newline="")):
            ans = (cache.get(r["ip"]) or {}).get(kind)
            if not ans:
                continue
            if kind == "ip2l":
                u = ans.get("usage_type") or "?"
                c = "MOB only" if u == "MOB" else ("MOB with other" if "MOB" in u.split("/") else "not MOB")
                net = ans.get("as") or "?"
            else:
                t = ans.get("traits") or {}
                c = "cellular" if (t.get("user_type") == "cellular" or t.get("connection_type") == "Cellular") \
                    else (t.get("user_type") or "?")
                net = t.get("autonomous_system_organization") or t.get("isp") or "?"
            cls[(r["provider"], r["country_req"])][c] += 1
            carriers[(r["provider"], r["country_req"])][net] += 1
        name = "mobile_share_ip2location.csv" if kind == "ip2l" else "mobile_share_maxmind.csv"
        with open(os.path.join(d, name), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Provider", "Country", "Class", "IPs"])
            for (p, cc), cnt in sorted(cls.items()):
                for c, n in sorted(cnt.items()):
                    w.writerow([p, cc.upper(), c, n])
        cname = "carrier_mix_ip2location.csv" if kind == "ip2l" else "carrier_mix_maxmind.csv"
        with open(os.path.join(d, cname), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Provider", "Country", "Network (ASN organization)", "IPs"])
            for (p, cc), cnt in sorted(carriers.items()):
                for net, n in cnt.most_common():
                    w.writerow([p, cc.upper(), net, n])
        written += [name, cname]
    return written


def copy_files(out, results, pairs, counters=""):
    os.makedirs(os.path.join(out, "scripts"), exist_ok=True)
    for s in PUBLIC_SCRIPTS:
        shutil.copy2(os.path.join(HERE, s), os.path.join(out, "scripts", s))
    for src, name in ((os.path.join(REPO, "public", "README.md"), "README.md"), (os.path.join(REPO, "public", "LICENSE"), "LICENSE"),
                      (os.path.join(REPO, "public", "gitignore"), ".gitignore")):
        shutil.copy2(src, os.path.join(out, name))
    os.makedirs(os.path.join(out, "results"), exist_ok=True)
    if results:
        shutil.copy2(results, os.path.join(out, "results", "results.xlsx"))
    if pairs:
        shutil.copy2(pairs, os.path.join(out, "results", "pairs.json"))
    if counters:
        shutil.copy2(counters, os.path.join(out, "results", "counters.csv"))


def scan(out, secrets_file=""):
    """Every text file: no IP address (except documentation ranges in examples), no forbidden string."""
    problems = []
    literal = []
    if secrets_file:
        literal = [s.strip() for s in open(secrets_file) if len(s.strip()) >= 6]
    for root, _dirs, files in os.walk(out):
        for fn in files:
            p = os.path.join(root, fn)
            if fn.endswith(".xlsx"):  # a zip of XML sheets: scan their text
                with zipfile.ZipFile(p) as z:
                    text = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".xml"))
            else:
                text = open(p, errors="replace").read()
            for m in IP_RE.finditer(text):
                s = m.group(0)
                try:
                    a = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if a.is_private or a.is_loopback or str(a).startswith(("203.0.113.", "198.51.100.", "192.0.2.", "2001:db8")) \
                        or s in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "0.0.0.0"):
                    continue
                problems.append("%s: IP address %s" % (os.path.relpath(p, out), s))
                break
            for pat in FORBIDDEN:
                if re.search(pat, text):
                    problems.append("%s: matches %s" % (os.path.relpath(p, out), pat))
            for i, s in enumerate(literal):
                if s in text:
                    problems.append("%s: contains private string #%d from the secrets file" % (os.path.relpath(p, out), i + 1))
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--ipq", required=True)
    ap.add_argument("--results", default="")
    ap.add_argument("--pairs", default="")
    ap.add_argument("--counters", default="", help="dashboard traffic counters CSV (results/counters.csv)")
    ap.add_argument("--out", default="release")
    ap.add_argument("--secrets", default="", help="private file, one login/key/address per line, to search for literally")
    a = ap.parse_args()
    if os.path.exists(a.out):
        sys.exit("%s exists; remove it first (the release is always built from scratch)" % a.out)
    h = hasher()
    n_files, n_rows = anonymize(a.raw, a.out, h)
    agg = aggregates(a.ipq, a.out)
    copy_files(a.out, a.results, a.pairs, a.counters)
    problems = scan(a.out, a.secrets)
    print("Raw CSV: %d files, %d rows, IPs hashed. Aggregates: %s." % (n_files, n_rows, ", ".join(agg) or "none"))
    if problems:
        print("NOT READY - remove these before publishing:")
        for p in problems[:30]:
            print("  " + p)
        sys.exit(1)
    print("Scan clean: no IP addresses, server names or credentials found. Release in %s" % a.out)


if __name__ == "__main__":
    main()
