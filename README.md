# AI-Based DNS Spoofing Anomaly Detection

A local, defensive demonstration of DNS record parsing, transparent protocol rules, Isolation Forest anomaly scoring, and a Streamlit dashboard. The built-in simulator works offline. Simulated records are explicitly labeled and are never represented as captured network traffic.

## Run on Windows 10/11

1. Install Python 3.11 (64-bit).
2. Open PowerShell in this folder and run `py -3.11 -m venv .venv`.
3. Activate with ` .\.venv\Scripts\Activate.ps1` (or use `.venv\Scripts\python.exe` directly).
4. Install: `python -m pip install -r requirements.txt`
5. Launch: `streamlit run app.py`

The app creates `data/events.db` and `models/isolation_forest.joblib` locally. Use the Simulation Lab first. No network access is needed for the demo.

## What it does

- Generates normal, suspicious, or mixed structured DNS events with optional reproducible seeds.
- Parses DNS from Scapy packets and local PCAP/PCAPNG files.
- Extracts interpretable numerical features without using raw domains, IPs, IDs, or timestamps as continuous model inputs.
- Applies explicit rule checks and an Isolation Forest trained only on generated normal training data. Its score indicates unusualness, not attack probability.
- Combines findings into `NORMAL`, `SUSPICIOUS`, `POTENTIAL_DNS_SPOOFING`, or `INVALID_OR_INCOMPLETE` and records results in SQLite.
- Exports simulation and PCAP records/results as CSV.

## Detection limits

Transaction ID/source inconsistencies and conflicting answers are protocol evidence, but still need context. Unmatched responses can result from capture loss. IP changes, TTL, frequency, and response time can be legitimate. The app reports potential spoofing or suspicious anomalies, not confirmed attacks. Ordinary Scapy parsing cannot inspect DNS over HTTPS or DNS over TLS payloads without an authorized decryption or endpoint data source.

## PCAP and live capture

PCAP/PCAPNG files are processed locally and read-only. The dashboard limits uploads to 20 MB. Live capture is deliberately an opt-in, selected-interface action; it filters for DNS UDP/TCP traffic and requires suitable capture permissions and Npcap on Windows. No packet transmission or spoofing is performed. If capture is unavailable, use simulation or PCAP upload.

## Layout

`app.py` dashboard; `dns_detector/` simulator, parser, features, rules, model, persistence, and orchestration; `tests/` core deterministic tests.
