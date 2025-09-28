#!/usr/bin/env python3
"""
HTTP Header Fingerprinter
Simple tool to fetch HTTP headers, page title and basic tech hints from a list of targets.

Usage:
    python http_fingerprint.py -u https://example.com
    python http_fingerprint.py -i targets.txt -o report.json -t 10

Author: Luis Miguel Martin Gonzalez
License: MIT
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import requests
from bs4 import BeautifulSoup
import json
import csv
from urllib.parse import urlparse
import socket
import sys
from typing import List, Dict, Any

DEFAULT_TIMEOUT = 6

COMMON_HEADERS = [
    "Server",
    "X-Powered-By",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "Set-Cookie",
    "X-Content-Type-Options",
]

TECH_HINTS = [
    ("WordPress", lambda headers, text: "wp-" in text or "wordpress" in text.lower()),
    ("PHP", lambda headers, text: "X-Powered-By" in headers and "php" in headers.get("X-Powered-By", "").lower()),
    ("nginx", lambda headers, text: "nginx" in headers.get("Server", "").lower()),
    ("Apache", lambda headers, text: "apache" in headers.get("Server", "").lower()),
    ("IIS", lambda headers, text: "microsoft-iis" in headers.get("Server", "").lower() or "iis" in headers.get("Server", "").lower()),
]


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    # if looks like host:port or host, default to http://
    return "http://" + raw


def fetch_one(target: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    result = {
        "target": target,
        "url": "",
        "status": None,
        "headers": {},
        "title": None,
        "hints": [],
        "error": None,
        "ip": None,
        "redirects": [],
    }
    url = normalize_target(target)
    result["url"] = url
    try:
        # Resolve IP for info
        parsed = urlparse(url)
        host = parsed.hostname
        try:
            ip = socket.gethostbyname(host) if host else None
            result["ip"] = ip
        except Exception:
            result["ip"] = None

        resp = requests.get(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": "CPMB-HTTP-FP/1.0"})
        result["status"] = resp.status_code
        # capture redirects
        result["redirects"] = [r.url for r in resp.history] if resp.history else []
        # headers: pick common headers + all as fallback
        headers = {k: v for k, v in resp.headers.items()}
        result["headers"] = {k: headers.get(k, "") for k in COMMON_HEADERS}
        # title
        content_type = resp.headers.get("Content-Type", "")
        text = ""
        if "text" in content_type or "html" in content_type or resp.text:
            text = resp.text
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else None
                result["title"] = title
            except Exception:
                result["title"] = None
        # hints
        lowered_text = (text or "").lower()
        for name, check in TECH_HINTS:
            try:
                if check(resp.headers, lowered_text):
                    result["hints"].append(name)
            except Exception:
                pass

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


def run_targets(targets: List[str], workers: int = 10, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_target = {ex.submit(fetch_one, t, timeout): t for t in targets if t}
        for fut in as_completed(future_to_target):
            try:
                res = fut.result()
            except Exception as e:
                res = {"target": future_to_target[fut], "error": str(e)}
            results.append(res)
    return results


def write_json(path: str, data: Any):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: str, data: List[Dict[str, Any]]):
    keys = ["target", "url", "ip", "status", "title", "hints", "error"]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for row in data:
            writer.writerow({k: json.dumps(row[k]) if isinstance(row.get(k), (list, dict)) else row.get(k) for k in keys})


def load_targets_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def parse_args():
    p = argparse.ArgumentParser(description="HTTP Header Fingerprinter - simple reconnaissance tool")
    p.add_argument("-u", "--url", help="Single URL or host (e.g., example.com or https://example.com)")
    p.add_argument("-i", "--input", help="File with targets (one per line)")
    p.add_argument("-o", "--output", help="Output file (json or csv). If omitted prints to stdout")
    p.add_argument("-t", "--threads", type=int, default=10, help="Concurrency (default 10)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout seconds (default {DEFAULT_TIMEOUT})")
    return p.parse_args()


def main():
    args = parse_args()
    targets = []
    if args.url:
        targets.append(args.url)
    if args.input:
        targets.extend(load_targets_from_file(args.input))
    if not targets:
        print("No targets provided. Use -u or -i. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Running on {len(targets)} target(s) with {args.threads} threads")
    results = run_targets(targets, workers=args.threads, timeout=args.timeout)
    if args.output:
        if args.output.lower().endswith(".json"):
            write_json(args.output, results)
            print(f"[+] JSON report written to {args.output}")
        elif args.output.lower().endswith(".csv"):
            write_csv(args.output, results)
            print(f"[+] CSV report written to {args.output}")
        else:
            # default to json
            write_json(args.output + ".json", results)
            print(f"[+] JSON report written to {args.output}.json")
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
