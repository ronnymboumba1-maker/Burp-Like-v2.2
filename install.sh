#!/bin/bash
set -e
echo "[*] Installation Burp-Like Web v2.2"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo ""
echo "[+] OK"
echo "    source venv/bin/activate"
echo "    python burp_like_web.py"
echo ""
echo "    Interface : http://127.0.0.1:5000"
echo "    Proxy     : 127.0.0.1:8080"
echo "    Certificat: ~/.mitmproxy/mitmproxy-ca-cert.pem"