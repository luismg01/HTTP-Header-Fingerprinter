# HTTP Header Fingerprinter

Simple reconnaissance tool to fetch HTTP headers, HTML title and simple tech hints.

## Quickstart

1. Create virtualenv and install:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
2. Execute one target:
```
python http_fingerprint.py -u https://example.com -o report.json
```
3. Execute target list:
```
python http_fingerprint.py -i targets.txt -o report.json -t 20
```
## Note

Non-intrusive tool, designed for permitted environments and demonstrations. Do not use against targets without authorization.