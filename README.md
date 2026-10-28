# Mobile Proxy Benchmark 2026: raw data and scripts

Raw measurements, test scripts and the results workbook behind the
[Mobile Proxy Benchmark 2026: 11 Providers Tested](https://floppydata.com/mobile-proxy-benchmark/)
published by Floppydata.

**Disclosure:** Floppydata is one of the 11 tested providers and also the publisher of this benchmark.
Every provider was tested with the same scripts, servers, countries and schedule. That is why the
raw data and the code are public: you can check the numbers yourself.

## What was tested

- **Period:** 24-27 October 2026 (UTC).
- **Providers (11):** Floppydata, Decodo, Oxylabs, Evomi, SOAX, DataImpulse, ProxyEmpire, NodeMaven, IPRoyal, Byteful, ResiProx.
  Rotating mobile proxies billed per GB, bought on regular terms.
- **Not tested:** Rayobyte (mobile only through sales, $250 minimum plan), Infatica (identity verification required),
  Proxy-Cheap (phone number and postal address required), Geonode and Webshare (no mobile proxies),
  Proxidize and Proxy-Seller (dedicated ports billed by time, not traffic).
- **Countries (12):** US, DE, GB, FR, ES, BR, IN, PL, UA, TR, VN, ID.
- **Test servers (3):** USA (Ashburn), Germany (Falkenstein), Singapore (Hetzner Cloud). In the files they are `us`, `de`, `sg`.
- **Tests:**
  1. Infrastructure: Success Rate, Latency, Duplicate Rate, Geo Accuracy, IPv6 share (Cloudflare trace, 100 requests per
     provider and country, 08:00 and 20:00 UTC).
  2. Targets: Google search (12 countries) and the Instagram profile page (US, DE, GB) as a phone browser
     (curl_cffi with the Chrome 131 Android TLS fingerprint, no JavaScript), 11:00 and 23:00 UTC.
  3. Sticky IP lifetime: 8 sessions per run, 30 minutes, one check every 30 seconds, four runs a day.
  4. TCP/OS fingerprint: p0f on our own HTTPS endpoint reads the TCP handshake of the exit device, 05:00 and 17:00 UTC.
  5. IP quality: Scamalytics and IPinfo Lite on 300 unique IPs per provider; Mobile IP Share and carrier mix from
     IP2Location.io (10,000 unique IPs per provider) and MaxMind GeoIP Insights (the first 1,000 of them). The two
     databases disagree for some providers, so both are reported side by side.
  6. Cost per Successful Request: provider traffic counters read in each dashboard on 28 October 2026, 06:32-07:45 UTC
     (`results/counters.csv`, with the source and notes for each provider). 1 GB = 1,000 MB.

Duplicate Rate is counted over the whole test (28,800 infrastructure requests per provider): 1 - unique IPs / successful
requests. `pairs.json` gives its 95% interval of differences as a delete-one-run jackknife, and the per-run rate
(`duplicate-run`) for reference. The `Shared IPs` sheet shows how many of each provider's exit IPs were also given out by
another provider.

The full method, limitations and conclusions are in the article. The sheet "Method and limits" of the workbook repeats them.

## Repository content

| Path | What it is |
|---|---|
| `data/raw/{us,de,sg}/infra_*.csv` | Infrastructure test, one row per request |
| `data/raw/{us,de,sg}/targets_*.csv` | Google and Instagram test, one row per request |
| `data/raw/{us,de,sg}/sticky_*.csv` | Sticky session checks, one row per check |
| `data/raw/{us,de,sg}/fingerprint_*.csv` | TCP/OS fingerprint, one row per request |
| `data/ip_quality_aggregated.csv` | Scamalytics and IPinfo results per provider (aggregated, no IP addresses) |
| `data/mobile_share_ip2location.csv`, `data/mobile_share_maxmind.csv` | Mobile IP classes per provider and country (counts) |
| `data/carrier_mix_ip2location.csv`, `data/carrier_mix_maxmind.csv` | Networks (ASN organizations) per provider and country (counts) |
| `results/results.xlsx` | Full results: all tables, confidence intervals, per-run trends, method notes |
| `results/pairs.json` | 95% intervals of pairwise differences (latency, Duplicate Rate, sticky lifetime) |
| `results/counters.csv` | Traffic used by each provider's own dashboard counter, with when and where it was read |
| `scripts/` | The test scripts, the analysis scripts and the script that built this release |

## Anonymization

Exit IP addresses belong to the providers' mobile pools, so they are not published.
In every `ip` column the real address is replaced by `ip_` plus 16 hex characters: a keyed hash (HMAC-SHA256)
with a random key that was used once and then discarded. The same address always gets the same value in all files,
so unique-IP counts, Duplicate Rate and sticky-session IP changes are unchanged. The hashes cannot be turned back
into addresses. The original logs, server addresses, credentials, API keys and the fingerprint endpoint address are
not published. No other columns were changed. `scripts/release.py` is the script that made this copy.

Because of this, the IP database steps (`ipquality.py`) cannot be re-run on this data. Their results are published
as aggregates in `data/`. To repeat them you need your own measurements and your own Scamalytics, IPinfo,
IP2Location.io and MaxMind access.

## Reproduce the numbers

You need Python 3.9+ with `pandas` and `openpyxl`.

```bash
pip install pandas openpyxl
mkdir -p work
for s in us de sg; do mkdir -p work/$s/data; cp data/raw/$s/*.csv work/$s/data/; done
python3 scripts/analyze.py --raw work --counters results/counters.csv --out my_results.xlsx
python3 scripts/pairs.py --raw work --out my_pairs.json
```

`my_results.xlsx` has the same sheets as `results/results.xlsx` except the IP quality and Mobile IP Share sheets, which
need the private IP-level data (their aggregates are in `data/`).
`pairs.py` uses only the standard library; with the default seed (2026) its output matches `results/pairs.json`.

## Run your own test

The scripts use the Python standard library, with two exceptions: `targets.py` needs `curl_cffi` for the phone browser
TLS fingerprint, and `analyze.py` needs pandas and openpyxl. `fingerprint.py serve` needs p0f on the server.

```bash
pip install curl_cffi                      # for targets.py
python3 scripts/bench.py setup             # enter provider credentials once (stored in providers.json, never commit it)
python3 scripts/bench.py check --all-countries
python3 scripts/bench.py run --server us
python3 scripts/targets.py --help
python3 scripts/sticky.py --help
python3 scripts/fingerprint.py --help
```

Credentials are entered through `setup` and are never part of the scripts. `providers.json` and `keys.json` are in `.gitignore`.

## Column reference

- **infra:** `run_id, ts_utc, server, provider, test, target, country_req, ok, sec, ip, ipv, geo_cf, colo, bytes, err`
  (`ok` 1/0, `sec` request time, `ipv` 4 or 6, `geo_cf` country reported by Cloudflare, `colo` Cloudflare data centre).
- **targets:** `run_id, ts_utc, server, provider, target, country_req, url, ok, status, sec, bytes, result, engine`
  (`result` is success, js_page or consent (Google let the IP in), captcha, blocked_NNN, login_wall, rate_limited,
  provider_restricted (the proxy refused the target) or an error type; `engine` is the curl_cffi fingerprint).
- **sticky:** `run_id, ts_utc, server, provider, fmt, session, country, t_sec, ok, ip, err`.
- **fingerprint:** `run_id, ts_utc, server, provider, country_req, ok, sec, ip, p0f_status, os, os_flavor, link, distance, err`.

## Licence

Code (`scripts/`): MIT, see `LICENSE`.
Data and workbook (`data/`, `results/`): CC BY 4.0. Please credit "Floppydata Mobile Proxy Benchmark 2026" and link to the article.

## Contact

Corrections and questions: open an issue in this repository.
