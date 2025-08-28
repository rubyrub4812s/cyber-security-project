#!/usr/bin/env python3
# app.py
# Author: @rubydoss
# Cyber Security Awareness Training App (Safe demo)
# All Rights Reserved © 2025

from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import time

app = Flask(__name__)

def simple_url_check(url):
    flags = []
    if not url:
        flags.append("No URL provided.")
        return flags

    try:
        p = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    except Exception:
        flags.append("URL parsing failed - malformed URL.")
        return flags

    if p.scheme != "https":
        flags.append("Site is not using HTTPS (no TLS) — insecure for credentials.")
    if p.netloc and p.netloc.count('.') > 2 and re.search(r'\d', p.netloc):
        flags.append("Domain looks complex (subdomain-heavy or contains numbers) — check carefully.")
    if p.hostname and len(p.hostname.split('-')) > 3:
        flags.append("Domain uses many hyphens — suspicious patterns sometimes use lookalike subdomains.")
    suspicious_tlds = {".ml", ".tk", ".cf", ".gq", ".ga"}
    for tld in suspicious_tlds:
        if p.netloc.endswith(tld):
            flags.append(f"Domain uses uncommon free TLD ({tld}) — check reputation.")
    return flags

def analyze_submission(username, password_field, page_url):
    observations = []
    tips = []

    if username and "@" in username:
        observations.append("You used an email-like username.")
    else:
        observations.append("You used a non-email username (common in some sites).")

    if password_field and len(password_field) < 8:
        tips.append("Password looks short — recommend using >=12 characters or a passphrase.")
    else:
        tips.append("Good: prefer long, unique passphrases and a password manager.")

    flags = simple_url_check(page_url)
    observations.extend(flags)
    if not flags:
        tips.append("URL basic checks OK — still verify the address and certificate in your browser.")
    else:
        tips.append("Review flagged items carefully before trusting the site. When in doubt, do not enter credentials.")

    tips.append("This is a training demo. **Never** enter real passwords on untrusted pages during exercises.")
    return {"observations": observations, "tips": tips, "timestamp": int(time.time())}

@app.route("/", methods=["GET"])
def index():
    return render_template("training_login.html")

@app.route("/submit", methods=["POST"])
def submit():
    username = request.form.get("username", "").strip()
    password_field = request.form.get("password", "")
    page_url = request.form.get("page_url", "").strip()
    result = analyze_submission(username=username, password_field=password_field, page_url=page_url)
    return render_template("result.html", result=result, username_display=(username or "<empty>"))

@app.route("/privacy", methods=["GET"])
def privacy():
    return "<h3>Privacy & Safety</h3><p>This training application does not store passwords.</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
