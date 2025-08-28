#!/usr/bin/env python3
# phish_detect.py
# Author: @rubydoss
# All Rights Reserved © 2025

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import tldextract
import sys
import re

HEADERS = {"User-Agent": "PhishDetect-Edu/1.0 (+https://example.com/)"}

def fetch(url, timeout=10):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return r
    except Exception as e:
        print(f"[error] Failed to fetch {url}: {e}")
        return None

def analyze(url):
    print(f"Analyzing: {url}\n")
    r = fetch(url)
    if not r:
        return

    parsed = urlparse(r.url)
    ext = tldextract.extract(r.url)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    print(f"Resolved URL: {r.url}")
    print(f"Scheme: {parsed.scheme}, Host: {parsed.netloc}, Registered domain: {registered}")

    if parsed.scheme != "https":
        print("[flag] Page is not HTTPS — credentials could be exposed in transit.")

    soup = BeautifulSoup(r.text, "html.parser")
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")
    print("Title:", repr(title))

    forms = soup.find_all("form")
    print("Forms found:", len(forms))
    for i, form in enumerate(forms, 1):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        action_abs = urljoin(r.url, action)
        action_host = urlparse(action_abs).netloc
        print(f" Form #{i}: method={method}, action={action_abs}")
        if action_host and action_host != parsed.netloc:
            print("  [flag] Form posts to a different domain -> possible credential exfiltration target.")

    resources = []
    for tag, attr in (("img","src"), ("script","src"), ("link","href")):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                resources.append(urljoin(r.url, val))
    hosts = set(urlparse(x).netloc for x in resources if urlparse(x).netloc)
    external_hosts = [h for h in hosts if h and h != parsed.netloc]
    print("External resource hosts:", len(external_hosts))

    if title:
        title_lower = title.lower()
        if any(term in title_lower for term in ["login", "sign in", "account"]) and registered not in title_lower:
            print("  [flag] Login-themed title without registered domain reference — lookalike indicator.")

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname or ""):
        print("  [note] Host is an IP address.")
    if parsed.hostname and parsed.hostname.count('-') >= 3:
        print("  [note] Domain contains many hyphens.")

    print("\nSummary: Heuristic tool — verify via certificate details and reputation services.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 phish_detect.py <url>")
        sys.exit(1)
    analyze(sys.argv[1])
