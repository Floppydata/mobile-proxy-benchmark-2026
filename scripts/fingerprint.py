#!/usr/bin/env python3
"""TCP/OS fingerprint test: which device really opens the connection behind a mobile proxy.

Two parts:

  On one test server (needs root and p0f: apt install p0f):
    p0f -i eth0 -s /run/p0f.sock -d 'tcp dst port 8090'
    python3 fingerprint.py serve --port 8090 --token SECRET

  On every test server (needs bench.py, providers.json, format_choice.json):
    python3 fingerprint.py run --server us --endpoint http://SERVER_IP:8090 --token SECRET
    python3 fingerprint.py summary

'serve' answers GET /fp with JSON: the client IP and what p0f saw in the TCP SYN of that
connection (OS guess, link type from the MSS/MTU, network distance from the TTL). Requests go
through the rotating proxy over plain HTTP, so the TCP connection comes from the exit device,
not from the provider's gateway. Android is reported by p0f as Linux; Windows, Mac OS X or a
plain 1500-byte Ethernet MTU behind a "mobile" IP point to a computer or a modem farm.

Only the Python standard library is used.
"""
import argparse
import csv
import datetime
import glob
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

FIELDS = ["run_id", "ts_utc", "server", "provider", "country_req", "ok", "sec", "ip",
          "p0f_status", "os", "os_flavor", "link", "distance", "err"]
P0F_QUERY_MAGIC = 0x50304601
P0F_RESP_MAGIC = 0x50304602
P0F_STATUS = {0x00: "bad_query", 0x10: "ok", 0x20: "no_match"}  # api.h P0F_STATUS_*
# our own endpoint uses a self-signed certificate; the reply carries no secrets
UNVERIFIED = ssl._create_unverified_context()
# struct p0f_api_response from p0f 3.x api.h (packed, host byte order)
P0F_RESP = struct.Struct("=IIIIIIIIIhBB32s32s32s32s32s32s")


# ---------------------------------------------------------------- p0f API
def p0f_query(sock_path, ip):
    addr = ipaddress.ip_address(ip)
    packed = addr.packed.ljust(16, b"\0")
    q = struct.pack("=IB16s", P0F_QUERY_MAGIC, 4 if addr.version == 4 else 6, packed)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(sock_path)
        s.sendall(q)
        buf = b""
        while len(buf) < P0F_RESP.size:
            chunk = s.recv(P0F_RESP.size - len(buf))
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    if len(buf) < P0F_RESP.size:
        return dict(p0f_status="short_reply")
    f = P0F_RESP.unpack(buf)
    if f[0] != P0F_RESP_MAGIC:
        return dict(p0f_status="bad_magic")

    def txt(b):
        return b.split(b"\0", 1)[0].decode(errors="replace")

    return dict(p0f_status=P0F_STATUS.get(f[1], str(f[1])), os=txt(f[12]), os_flavor=txt(f[13]),
                link=txt(f[16]), distance=f[9])


# -------------------------------------------------------------------- serve
def make_handler(sock_path, token):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path != "/fp" or (token and q.get("k", [""])[0] != token):
                self.send_response(404)
                self.end_headers()
                return
            ip = self.client_address[0]
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            time.sleep(0.2)  # let p0f process the SYN of this connection
            try:
                info = p0f_query(sock_path, ip)
            except Exception as e:  # noqa: BLE001
                info = dict(p0f_status="api_error: %s" % str(e)[:40])
            body = json.dumps(dict(ip=ip, **info)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            pass

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def finish_request(self, request, client_address):
        if isinstance(request, ssl.SSLSocket):
            # TLS handshake in the worker thread, so one slow mobile client never blocks accept()
            request.settimeout(20)
            request.do_handshake()
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        pass  # broken or slow clients are normal here


def cmd_serve(args):
    srv = Server(("0.0.0.0", args.port), make_handler(args.p0f_socket, args.token))
    if args.tls_cert:
        # HTTPS: the proxy opens a CONNECT tunnel, which every provider supports; plain HTTP to a
        # bare IP and port is refused by most of them. p0f still sees the exit device's TCP SYN.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    print("Fingerprint endpoint on port %d (%s), p0f socket %s. Stop with Ctrl+C." % (
        args.port, "https" if args.tls_cert else "http", args.p0f_socket))
    srv.serve_forever()


# ---------------------------------------------------------------------- run
def one_fp(proxy, url, run_id, server, provider, cc, timeout):
    t = time.time()
    row = dict(run_id=run_id, ts_utc=bench.utcnow(), server=server, provider=provider, country_req=cc,
               ok=0, sec=0.0, ip="", p0f_status="", os="", os_flavor="", link="", distance="", err="")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
                                             urllib.request.HTTPSHandler(context=UNVERIFIED))
        with opener.open(url, timeout=timeout) as r:
            d = json.loads(r.read(4096).decode(errors="replace"))
        row.update(ok=1, **{k: d.get(k, "") for k in ("ip", "p0f_status", "os", "os_flavor", "link", "distance")})
    except Exception as e:  # noqa: BLE001
        row["err"] = bench.classify_error(e)
    row["sec"] = round(time.time() - t, 3)
    return row


def cmd_run(args):
    cfg = bench.load_config()["providers"]
    choice = bench.load_choice()
    keys = args.providers.split(",") if args.providers else sorted(k for k in cfg if k in choice["rotating"])
    countries = args.countries.split(",")
    run_id = args.run_id or time.strftime("%Y%m%d-%H%M", time.gmtime())
    url = args.endpoint.rstrip("/") + "/fp" + ("?k=" + urllib.parse.quote(args.token) if args.token else "")
    os.makedirs(bench.DATA, exist_ok=True)
    path = os.path.join(bench.DATA, "fingerprint_%s_%s.csv" % (args.server, run_id))
    print("[%s] fingerprint run %s: %d providers x %d countries x %d requests"
          % (bench.utcnow(), run_id, len(keys), len(countries), args.n))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for cc in countries:
            order = keys[:]
            random.shuffle(order)
            for key in order:
                fmt = bench.rotating_format(key, choice)
                with ThreadPoolExecutor(max_workers=args.workers) as ex:
                    batch = list(ex.map(lambda i: one_fp(bench.proxy_url(cfg[key], fmt, cc), url, run_id,
                                                         args.server, key, cc, args.timeout), range(args.n)))
                w.writerows(batch)
                f.flush()
                print("[%s] %-12s %-3s %d/%d ok" % (bench.utcnow(), key, cc.upper(), sum(r["ok"] for r in batch), args.n))
    print("[%s] finished, raw data in %s" % (bench.utcnow(), path))


def cmd_schedule(args):
    tag = "# mbench-fp"
    hours = [int(h) for h in args.hours.split(",")]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    now = datetime.datetime.now(datetime.timezone.utc)
    me = os.path.abspath(__file__)
    token = "$(cat %s)" % os.path.abspath(args.token_file) if args.token_file else ""
    lines = []
    for d in range(args.start_in_days, args.start_in_days + args.days):
        day = today + datetime.timedelta(days=d)
        for h in hours:
            at_utc = datetime.datetime(day.year, day.month, day.day, h, args.minute, tzinfo=datetime.timezone.utc)
            if at_utc <= now:
                continue
            at = at_utc.astimezone()
            lines.append("%d %d %d %d * cd %s && %s %s run --server %s --endpoint %s --token %s >> %s 2>&1 %s" % (
                at.minute, at.hour, at.day, at.month, bench.HOME, sys.executable, me, args.server,
                args.endpoint, token, os.path.join(bench.LOGS, "cron-fp.log"), tag))
    for ln in lines:
        print("  " + ln)
    if not args.install:
        print("\nNothing installed. Add --install to write these into cron.")
        return
    os.makedirs(bench.LOGS, exist_ok=True)
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    keep = [ln for ln in cur.stdout.splitlines() if tag not in ln] if cur.returncode == 0 else []
    subprocess.run(["crontab", "-"], input="\n".join(keep + lines) + "\n", text=True, check=True)
    print("\nInstalled %d fingerprint runs into cron." % len(lines))


# ------------------------------------------------------------------ summary
def os_group(r):
    name = (r["os"] or "").lower()
    if r["p0f_status"] != "ok" or not name or name == "???":
        return "unknown"
    for g in ("windows", "mac os", "ios", "linux", "freebsd"):
        if g in name:
            return g
    return "other"


def cmd_summary(args):
    rows = []
    for p in sorted(glob.glob(os.path.join(bench.DATA, "fingerprint_*.csv"))):
        with open(p, newline="") as f:
            rows += [r for r in csv.DictReader(f) if r["ok"] == "1"]
    if not rows:
        sys.exit("No fingerprint data yet.")
    by = defaultdict(list)
    for r in rows:
        by[r["provider"]].append(r)
    groups = ["linux", "windows", "mac os", "ios", "other", "unknown"]
    head = "%-12s| %-7s| %s| %-24s| %s" % ("Provider", "Answers", "".join("%-10s" % g for g in groups),
                                           "Ethernet MTU 1500 (95% CI)", "Top link types")
    print(head)
    print("-" * len(head))
    for prov, rs in sorted(by.items()):
        c = Counter(os_group(r) for r in rs)
        n = len(rs)
        eth = sum(1 for r in rs if r["link"].lower().startswith("ethernet"))
        known_link = [r for r in rs if r["link"] and r["link"] != "???"]
        links = Counter(r["link"] for r in known_link).most_common(2)
        print("%-12s| %-7d| %s| %-24s| %s" % (
            bench.PROVIDERS.get(prov, {}).get("label", prov), n,
            "".join("%-10s" % ("%.0f%%" % (100.0 * c[g] / n)) for g in groups),
            bench.fmt_rate(eth, len(known_link)) if known_link else "n/a",
            ", ".join("%s x%d" % kv for kv in links)))
    print("\nAndroid shows as linux in p0f. windows / mac os, or 'Ethernet or modem' (MTU 1500) behind a mobile IP")
    print("point to a computer or a modem farm rather than a phone.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8090)
    s.add_argument("--p0f-socket", default="/run/p0f.sock")
    s.add_argument("--token", default="", help="requests without ?k=TOKEN get 404")
    s.add_argument("--tls-cert", default="", help="serve HTTPS with this certificate (PEM)")
    s.add_argument("--tls-key", default="")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("run")
    s.add_argument("--server", required=True)
    s.add_argument("--endpoint", required=True, help="e.g. http://203.0.113.5:8090")
    s.add_argument("--token", default="")
    s.add_argument("--n", type=int, default=10, help="requests per provider and country")
    s.add_argument("--countries", default=",".join(bench.COUNTRIES))
    s.add_argument("--providers", default="")
    s.add_argument("--workers", type=int, default=5)
    s.add_argument("--timeout", type=float, default=30)
    s.add_argument("--run-id", default="")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("summary")
    s.set_defaults(fn=cmd_summary)

    s = sub.add_parser("schedule")
    s.add_argument("--server", required=True)
    s.add_argument("--endpoint", required=True)
    s.add_argument("--token-file", default="", help="file with the token, read by cron at run time")
    s.add_argument("--days", type=int, default=4)
    s.add_argument("--hours", default="5,17", help="UTC hours, comma separated")
    s.add_argument("--minute", type=int, default=0)
    s.add_argument("--start-in-days", type=int, default=1)
    s.add_argument("--install", action="store_true")
    s.set_defaults(fn=cmd_schedule)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
