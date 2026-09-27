# BURP-LIKE WEB v2.2 — JATHNIEL EDITION

Proxy d'interception HTTP/HTTPS + interface web moderne (single-file).

## Fonctionnalités
- Intercept (forward / drop / modify)
- History searchable + détail
- Intruder (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- Scanner passif (SQLi, XSS, LFI, SSRF, headers, cookies…)
- Repeater
- Decoder (URL, B64, Hex, HTML, JWT, hash)
- Export JSON / HTML
- Templates 100 % embarqués (aucun dossier templates/)

## Installation
```bash
chmod +x install.sh
./install.sh
source venv/bin/activate
python burp_like_web.py