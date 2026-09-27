#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BURP-LIKE WEB v2.2 — JATHNIEL EDITION
Proxy d'interception HTTP/HTTPS + interface web moderne (single-file).
Templates HTML/CSS/JS 100 % embarqués.
Support WSL (écoute 0.0.0.0 + affichage IP réelle).
"""

import os
import sys
import json
import time
import asyncio
import base64
import html as html_lib
import re
import sqlite3
import threading
import hashlib
import urllib.parse
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, Response, render_template_string

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITM_OK = True
except ImportError:
    MITM_OK = False
    print("[!] mitmproxy non installé : pip install mitmproxy")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] requests non installé : pip install requests")


# ==================== CONFIG ====================

APP_DIR = Path(__file__).parent
DB_PATH = Path.home() / ".burp_like_web" / "history.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

PROXY_PORT = 8080
WEB_PORT = 5000


def get_local_ips():
    """Retourne les IPs locales (utile pour WSL depuis Windows)."""
    ips = []
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            ips.append(ip)
        s.close()
    except Exception:
        pass
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
        for ip in out.strip().split():
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


# ==================== DÉCODAGE ====================

class Decoder:
    """Décode automatiquement les valeurs (URL, Base64, HTML, Hex, JSON, JWT)."""

    @staticmethod
    def decode_value(value):
        result = {"original": value, "decoded": value, "variants": []}
        if not value or not isinstance(value, str):
            return result

        try:
            url_decoded = urllib.parse.unquote(value)
            if url_decoded != value:
                result["variants"].append({"type": "url", "value": url_decoded})
                result["decoded"] = url_decoded
        except Exception:
            pass

        try:
            if re.match(r"^[A-Za-z0-9+/]+=*$", value) and len(value) % 4 == 0 and len(value) > 4:
                b64 = base64.b64decode(value).decode("utf-8", errors="ignore")
                if b64.isprintable():
                    result["variants"].append({"type": "base64", "value": b64})
        except Exception:
            pass

        try:
            html_dec = html_lib.unescape(value)
            if html_dec != value:
                result["variants"].append({"type": "html", "value": html_dec})
        except Exception:
            pass

        try:
            if re.match(r"^[0-9a-fA-F]+$", value) and len(value) % 2 == 0 and len(value) >= 4:
                hex_dec = bytes.fromhex(value).decode("utf-8", errors="ignore")
                if hex_dec.isprintable():
                    result["variants"].append({"type": "hex", "value": hex_dec})
        except Exception:
            pass

        try:
            json_data = json.loads(value)
            result["variants"].append({
                "type": "json",
                "value": json.dumps(json_data, indent=2, ensure_ascii=False)
            })
        except Exception:
            pass

        if value.count(".") == 2:
            try:
                parts = value.split(".")
                pad = lambda s: s + "=" * (-len(s) % 4)
                h = base64.urlsafe_b64decode(pad(parts[0])).decode("utf-8", errors="ignore")
                p = base64.urlsafe_b64decode(pad(parts[1])).decode("utf-8", errors="ignore")
                try:
                    h_pretty = json.dumps(json.loads(h), indent=2)
                    p_pretty = json.dumps(json.loads(p), indent=2)
                except Exception:
                    h_pretty, p_pretty = h, p
                result["variants"].append({
                    "type": "jwt",
                    "value": f"Header:\n{h_pretty}\n\nPayload:\n{p_pretty}"
                })
            except Exception:
                pass

        return result

    @staticmethod
    def decode_body(body, content_type=""):
        result = {
            "original": body, "decoded": body, "params": {},
            "type": "raw", "pretty": body,
        }
        if not body:
            return result

        try:
            json_data = json.loads(body)
            result["type"] = "json"
            result["pretty"] = json.dumps(json_data, indent=2, ensure_ascii=False)
            result["decoded"] = result["pretty"]
            if isinstance(json_data, dict):
                for k, v in json_data.items():
                    if isinstance(v, str):
                        result["params"][k] = Decoder.decode_value(v)
            elif isinstance(json_data, list):
                for i, item in enumerate(json_data[:20]):
                    if isinstance(item, str):
                        result["params"][f"[{i}]"] = Decoder.decode_value(item)
            return result
        except Exception:
            pass

        try:
            params = urllib.parse.parse_qs(body, keep_blank_values=True)
            if params:
                result["type"] = "form"
                lines = []
                for k, vals in params.items():
                    v = vals[0] if vals else ""
                    d = Decoder.decode_value(v)
                    result["params"][k] = d
                    lines.append(f"{k} = {d['decoded']}")
                result["decoded"] = "\n".join(lines)
                result["pretty"] = result["decoded"]
                return result
        except Exception:
            pass

        decoded = Decoder.decode_value(body)
        if decoded["variants"]:
            result["decoded"] = decoded["decoded"]
            result["pretty"] = decoded["decoded"]
            result["variants"] = decoded["variants"]

        return result


# ==================== BASE DE DONNÉES ====================

class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT, url TEXT, host TEXT, path TEXT,
            headers TEXT, body TEXT,
            status INTEGER, response_headers TEXT, response_body TEXT,
            timestamp TEXT, modified INTEGER DEFAULT 0,
            response_size INTEGER DEFAULT 0,
            content_type_req TEXT, content_type_resp TEXT,
            decoded_body TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT, type TEXT, url TEXT,
            description TEXT, evidence TEXT, timestamp TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_req_host ON requests(host)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_req_method ON requests(method)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_req_status ON requests(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity)")
        conn.commit()
        conn.close()

    def insert(self, req):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute("""INSERT INTO requests
                (method, url, host, path, headers, body, status,
                 response_headers, response_body, timestamp, modified,
                 response_size, content_type_req, content_type_resp, decoded_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (req.get("method", ""), req.get("url", ""), req.get("host", ""),
                 req.get("path", ""), json.dumps(req.get("headers", {})),
                 req.get("body", ""), req.get("status", 0),
                 json.dumps(req.get("response_headers", {})),
                 req.get("response_body", ""), datetime.now().isoformat(),
                 1 if req.get("modified") else 0,
                 req.get("response_size", 0),
                 req.get("content_type_req", ""),
                 req.get("content_type_resp", ""),
                 json.dumps(req.get("decoded_body", {}))))
            conn.commit()
            req_id = c.lastrowid
            conn.close()
            return req_id

    def get_by_id(self, req_id):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("SELECT * FROM requests WHERE id = ?", (req_id,))
        row = c.fetchone()
        conn.close()
        return row

    def search(self, method="", status="", host="", search=""):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        query = """SELECT id, method, host, path, status, response_size,
                   timestamp, content_type_resp, modified
                   FROM requests WHERE 1=1"""
        params = []
        if method:
            query += " AND method = ?"
            params.append(method)
        if status:
            query += " AND status = ?"
            params.append(status)
        if host:
            query += " AND host LIKE ?"
            params.append(f"%{host}%")
        if search:
            query += " AND (url LIKE ? OR body LIKE ? OR response_body LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        query += " ORDER BY id DESC LIMIT 500"
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows

    def stats(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM requests")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM requests WHERE method='GET'")
        gets = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM requests WHERE method='POST'")
        posts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        findings = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM requests WHERE modified=1")
        modified = c.fetchone()[0]
        conn.close()
        return {
            "total": total, "get": gets, "post": posts,
            "findings": findings, "modified": modified
        }

    def insert_finding(self, finding):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute("""INSERT INTO findings
                (severity, type, url, description, evidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (finding.get("severity", "info"), finding.get("type", ""),
                 finding.get("url", ""), finding.get("description", ""),
                 finding.get("evidence", "")[:500], datetime.now().isoformat()))
            conn.commit()
            conn.close()

    def get_findings(self, limit=200):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("""SELECT id, severity, type, url, description, evidence, timestamp
                    FROM findings ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END, id DESC LIMIT ?""", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def clear(self):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute("DELETE FROM requests")
            c.execute("DELETE FROM findings")
            conn.commit()
            conn.close()

    def export_json(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 1000")
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        return rows


# ==================== SIGNAL BUS ====================

class SignalBus:
    def __init__(self):
        self.pending_requests = []
        self.lock = threading.Lock()
        self.events = {}
        self.modifications = {}
        self.live_captures = []
        self.intercept_enabled = True

    def add_pending(self, req_data, event_key):
        with self.lock:
            self.pending_requests.append({"data": req_data, "key": event_key})
            event = threading.Event()
            self.events[event_key] = event
        return event

    def get_pending(self):
        with self.lock:
            return list(self.pending_requests)

    def apply_modification(self, event_key, modifications):
        with self.lock:
            self.modifications[event_key] = modifications
            if event_key in self.events:
                self.events[event_key].set()

    def consume_modification(self, event_key):
        with self.lock:
            mods = self.modifications.pop(event_key, {})
            self.pending_requests = [p for p in self.pending_requests if p["key"] != event_key]
            if event_key in self.events:
                del self.events[event_key]
            return mods

    def add_live_capture(self, capture):
        with self.lock:
            self.live_captures.append(capture)
            if len(self.live_captures) > 200:
                self.live_captures = self.live_captures[-200:]

    def get_live_captures(self, limit=50):
        with self.lock:
            return list(self.live_captures[-limit:])


signal_bus = SignalBus()
db = Database()


# ==================== SCANNER PASSIF ====================

class PassiveScanner:
    SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "mysqli_", "pg_query", "ora-",
        "sqlite_", "unclosed quotation", "microsoft ole db",
        "odbc drivers", "jdbc", "postgresql",
    ]
    LFI_PATTERNS = [
        "root:x:0:0:", "daemon:x:", "bin:x:", "[boot loader]",
        "[extensions]", "for 16-bit app support",
    ]
    SSRF_INDICATORS = [
        "169.254.169.254", "metadata.google", "localhost:",
        "file://", "gopher://",
    ]
    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("MEDIUM", "HSTS manquant"),
        "Content-Security-Policy": ("MEDIUM", "CSP manquant"),
        "X-Frame-Options": ("LOW", "Clickjacking possible"),
        "X-Content-Type-Options": ("LOW", "MIME sniffing possible"),
        "Referrer-Policy": ("LOW", "Referrer leak possible"),
    }

    def __init__(self, db):
        self.db = db

    def analyze(self, req_data):
        url = req_data.get("url", "")
        req_body = req_data.get("body", "")
        resp_body = req_data.get("response_body", "")
        resp_headers = req_data.get("response_headers", {})

        body_low = resp_body.lower()
        for err in self.SQLI_ERRORS:
            if err.lower() in body_low:
                self._add("HIGH", "SQL Injection (error-based)", url,
                          f"Erreur SQL visible : {err}", resp_body[:300])
                break

        for key, value in urllib.parse.parse_qs(req_body).items():
            if value and value[0] and len(value[0]) > 3 and value[0] in resp_body:
                if any(x in value[0].lower() for x in ["<script", "onerror", "javascript:"]):
                    self._add("MEDIUM", "XSS Reflected", url,
                              f"Payload '{value[0][:50]}' refléché", "")
                    break

        for pat in self.LFI_PATTERNS:
            if pat in resp_body:
                self._add("CRITICAL", "LFI", url,
                          "Contenu de fichier système détecté", pat)
                break

        for ind in self.SSRF_INDICATORS:
            if ind in resp_body.lower():
                self._add("HIGH", "SSRF", url, f"Indicateur SSRF : {ind}", "")
                break

        resp_h_lower = {k.lower(): v for k, v in resp_headers.items()}
        for header, (sev, desc) in self.SECURITY_HEADERS.items():
            if header.lower() not in resp_h_lower:
                self._add(sev, "Missing Security Header", url, desc, "")

        set_cookie = (resp_headers.get("Set-Cookie", "") or
                      resp_headers.get("set-cookie", ""))
        if set_cookie:
            if "Secure" not in set_cookie and url.startswith("https"):
                self._add("MEDIUM", "Cookie without Secure", url,
                          "Cookie sans flag Secure", set_cookie[:200])
            if "HttpOnly" not in set_cookie:
                self._add("LOW", "Cookie without HttpOnly", url,
                          "Cookie sans flag HttpOnly", set_cookie[:200])

        if "Index of /" in resp_body:
            self._add("MEDIUM", "Directory Listing", url, "Listing activé", "")

        for pat in ["Traceback (most recent call last)", "at java.lang.",
                    "System.NullReferenceException", "Warning: ",
                    "Fatal error:"]:
            if pat in resp_body:
                self._add("MEDIUM", "Information Disclosure", url,
                          f"Debug visible : {pat}", "")
                break

    def _add(self, severity, vtype, url, description, evidence):
        self.db.insert_finding({
            "severity": severity, "type": vtype, "url": url,
            "description": description, "evidence": evidence,
        })


scanner = PassiveScanner(db)


# ==================== MITMPROXY ADDON ====================

class InterceptAddon:
    def _in_scope(self, host):
        return True

    def request(self, flow):
        try:
            host = flow.request.host
            if not self._in_scope(host):
                return

            body = flow.request.get_text() if flow.request.content else ""
            content_type = flow.request.headers.get("Content-Type", "")
            decoded_body = Decoder.decode_body(body, content_type)

            req_data = {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body": body,
                "content_type_req": content_type,
                "decoded_body": decoded_body,
            }

            flow.metadata["req_data"] = req_data
            flow.metadata["start_time"] = time.time()

            if signal_bus.intercept_enabled:
                event_key = f"{flow.request.pretty_url}_{id(flow)}"
                event = signal_bus.add_pending(req_data, event_key)
                event.wait(timeout=120)
                mods = signal_bus.consume_modification(event_key)

                if mods.get("drop"):
                    flow.response = http.Response.make(
                        503, b"Dropped by Burp-Like Web",
                        {"Content-Type": "text/plain"}
                    )
                    return
                if "method" in mods:
                    flow.request.method = mods["method"]
                if "url" in mods:
                    parsed = urllib.parse.urlparse(mods["url"])
                    flow.request.scheme = parsed.scheme
                    flow.request.host = parsed.hostname or host
                    if parsed.port:
                        flow.request.port = parsed.port
                    flow.request.path = parsed.path or "/"
                    if parsed.query:
                        flow.request.path += "?" + parsed.query
                if "headers" in mods:
                    flow.request.headers.clear()
                    for k, v in mods["headers"].items():
                        flow.request.headers[k] = v
                if "body" in mods:
                    flow.request.set_text(mods["body"])
        except Exception as e:
            print(f"[ADDON] Erreur request: {e}")

    def response(self, flow):
        try:
            host = flow.request.host
            if not self._in_scope(host):
                return

            req_data = flow.metadata.get("req_data", {})
            start_time = flow.metadata.get("start_time", time.time())

            resp_body = flow.response.get_text() if flow.response.content else ""
            resp_headers = dict(flow.response.headers)
            content_type_resp = flow.response.headers.get("Content-Type", "")

            full_data = {
                **req_data,
                "status": flow.response.status_code,
                "response_headers": resp_headers,
                "response_body": resp_body,
                "response_size": len(resp_body),
                "content_type_resp": content_type_resp,
                "response_time": time.time() - start_time,
            }

            db.insert(full_data)

            try:
                scanner.analyze(full_data)
            except Exception as e:
                print(f"[SCANNER] Erreur: {e}")

            signal_bus.add_live_capture({
                "method": full_data.get("method", ""),
                "url": full_data.get("url", ""),
                "host": host,
                "status": full_data["status"],
                "size": full_data["response_size"],
                "time": round(full_data["response_time"], 3),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "content_type": content_type_resp.split(";")[0],
            })
        except Exception as e:
            print(f"[ADDON] Erreur response: {e}")


# ==================== PROXY SERVER ====================

class ProxyServer(threading.Thread):
    """Thread qui lance mitmproxy avec son propre event loop asyncio."""

    def __init__(self, port=8080):
        super().__init__(daemon=True)
        self.port = port
        self.master = None
        self.addon = None
        self.loop = None
        self.ready = threading.Event()

    def run(self):
        if not MITM_OK:
            print("[PROXY] mitmproxy non installé")
            return

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.loop.run_until_complete(self._run_master())
        except Exception as e:
            print(f"[PROXY] Erreur: {e}")
        finally:
            try:
                self.loop.close()
            except Exception:
                pass

    async def _run_master(self):
        # 0.0.0.0 = accessible depuis Windows (WSL)
        opts = options.Options(
            listen_host="0.0.0.0",
            listen_port=self.port,
        )
        try:
            self.master = DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
                loop=self.loop,
            )
        except TypeError:
            self.master = DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
            )

        self.addon = InterceptAddon()
        self.master.addons.add(self.addon)
        print(f"[PROXY] Démarré sur 0.0.0.0:{self.port}")
        self.ready.set()
        await self.master.run()

    def shutdown(self):
        if self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass


# ==================== HELPERS ====================

def content_kind(content_type, body):
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if "javascript" in ct:
        return "js"
    if "css" in ct:
        return "css"
    if body and body.strip().startswith(("{", "[")):
        return "json"
    if body and body.strip().startswith("<"):
        return "xml"
    return "text"


# ==================== TEMPLATES EMBARQUÉS ====================

BASE_CSS = """
:root {
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #21262d;
  --border: #30363d;
  --text: #e6edf3;
  --text2: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --orange: #d29922;
  --purple: #a371f7;
  --cyan: #39c5cf;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  display: flex;
  min-height: 100vh;
  font-size: 14px;
}
.sidebar {
  width: 220px;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  position: fixed;
  height: 100vh;
  z-index: 100;
}
.sidebar .logo {
  padding: 20px 16px;
  font-size: 18px;
  font-weight: 700;
  color: var(--accent);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
}
.sidebar nav { flex: 1; padding: 12px 0; }
.sidebar a {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 18px;
  color: var(--text2);
  text-decoration: none;
  transition: all 0.15s;
  border-left: 3px solid transparent;
}
.sidebar a:hover, .sidebar a.active {
  background: var(--bg3);
  color: var(--text);
  border-left-color: var(--accent);
}
.sidebar .footer {
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--text2);
}
.main {
  margin-left: 220px;
  flex: 1;
  padding: 24px;
  max-width: 1400px;
}
h1 { font-size: 22px; margin-bottom: 20px; color: var(--text); }
h2 { font-size: 16px; margin: 16px 0 10px; color: var(--accent); }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}
.card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}
.card .num { font-size: 28px; font-weight: 700; color: var(--accent); }
.card .label { font-size: 12px; color: var(--text2); margin-top: 4px; }
.btn {
  background: var(--bg3);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 7px 14px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  transition: all 0.15s;
}
.btn:hover { background: var(--border); }
.btn-primary { background: var(--accent); color: #0d1117; border-color: var(--accent); font-weight: 600; }
.btn-primary:hover { opacity: 0.9; }
.btn-danger { background: var(--red); color: white; border-color: var(--red); }
.btn-success { background: var(--green); color: #0d1117; border-color: var(--green); }
.btn-sm { padding: 4px 10px; font-size: 12px; }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg2);
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--border);
}
th, td {
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
th { background: var(--bg3); color: var(--text2); font-weight: 600; position: sticky; top: 0; }
tr:hover { background: rgba(88,166,255,0.05); }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  color: white;
}
.badge-get { background: #238636; }
.badge-post { background: #1f6feb; }
.badge-put { background: #9e6a03; }
.badge-delete { background: #da3633; }
.badge-other { background: #6e7681; }
.sev-CRITICAL { background: #da3633; }
.sev-HIGH { background: #d29922; }
.sev-MEDIUM { background: #9e6a03; }
.sev-LOW { background: #1f6feb; }
.status-2 { color: var(--green); }
.status-3 { color: var(--cyan); }
.status-4 { color: var(--orange); }
.status-5 { color: var(--red); }
.input, select, textarea {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  width: 100%;
  font-family: 'Cascadia Code', 'Consolas', monospace;
}
textarea { min-height: 120px; resize: vertical; }
.form-row { display: flex; gap: 10px; margin-bottom: 10px; align-items: center; }
.form-row label { min-width: 80px; color: var(--text2); font-size: 13px; }
.toolbar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
.panel {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
}
pre, .code {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  overflow-x: auto;
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow-y: auto;
}
.tabs { display: flex; gap: 4px; margin-bottom: 12px; }
.tab {
  padding: 8px 16px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 6px 6px 0 0;
  cursor: pointer;
  color: var(--text2);
}
.tab.active { background: var(--bg2); color: var(--accent); border-bottom-color: var(--bg2); }
.split { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 900px) { .split { grid-template-columns: 1fr; } .sidebar { width: 60px; } .main { margin-left: 60px; } .sidebar .logo span, .sidebar a span { display: none; } }
.empty { text-align: center; padding: 40px; color: var(--text2); }
.live-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; display: inline-block; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
"""

BASE_JS = """
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }
function badgeMethod(m) {
  const map = {GET:'badge-get',POST:'badge-post',PUT:'badge-put',DELETE:'badge-delete'};
  return `<span class="badge ${map[m]||'badge-other'}">${m}</span>`;
}
function statusClass(s) {
  if (!s) return '';
  const c = Math.floor(s/100);
  return `status-${c}`;
}
async function api(url, opts={}) {
  const r = await fetch(url, opts);
  return r.json();
}
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
"""

LAYOUT = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} — Burp-Like Web</title>
<style>""" + BASE_CSS + """</style>
</head>
<body>
<aside class="sidebar">
  <div class="logo">🔷 <span>Burp-Like</span></div>
  <nav>
    <a href="/" class="{{ 'active' if page=='dashboard' else '' }}">📊 <span>Dashboard</span></a>
    <a href="/intercept" class="{{ 'active' if page=='intercept' else '' }}">⏸ <span>Intercept</span></a>
    <a href="/history" class="{{ 'active' if page=='history' else '' }}">📜 <span>History</span></a>
    <a href="/intruder" class="{{ 'active' if page=='intruder' else '' }}">💣 <span>Intruder</span></a>
    <a href="/scanner" class="{{ 'active' if page=='scanner' else '' }}">🔍 <span>Scanner</span></a>
    <a href="/repeater" class="{{ 'active' if page=='repeater' else '' }}">🔁 <span>Repeater</span></a>
    <a href="/decoder" class="{{ 'active' if page=='decoder' else '' }}">🔓 <span>Decoder</span></a>
  </nav>
  <div class="footer">
    Proxy : 0.0.0.0:8080<br>
    v2.2 — Jathniel
  </div>
</aside>
<main class="main">
  {{ content | safe }}
</main>
<script>""" + BASE_JS + """</script>
{{ extra_js | safe }}
</body>
</html>
"""

DASHBOARD_CONTENT = """
<h1>📊 Dashboard</h1>
<div class="cards" id="stats">
  <div class="card"><div class="num" id="s-total">—</div><div class="label">Requêtes</div></div>
  <div class="card"><div class="num" id="s-get">—</div><div class="label">GET</div></div>
  <div class="card"><div class="num" id="s-post">—</div><div class="label">POST</div></div>
  <div class="card"><div class="num" id="s-find">—</div><div class="label">Findings</div></div>
  <div class="card"><div class="num" id="s-mod">—</div><div class="label">Modifiées</div></div>
  <div class="card"><div class="num" id="s-pend">—</div><div class="label">En attente</div></div>
</div>
<div class="toolbar">
  <button class="btn" id="btn-toggle">Toggle Intercept</button>
  <button class="btn btn-danger" id="btn-clear">Vider l'historique</button>
  <a class="btn" href="/api/export/json">Export JSON</a>
  <a class="btn" href="/api/export/html">Export HTML</a>
  <span id="intercept-status" style="margin-left:12px;color:var(--text2)"></span>
</div>
<h2><span class="live-dot"></span> Live captures</h2>
<div class="panel" style="max-height:420px;overflow-y:auto">
  <table>
    <thead><tr><th>Heure</th><th>Méthode</th><th>Host</th><th>Status</th><th>Taille</th><th>Temps</th><th>Type</th></tr></thead>
    <tbody id="live-body"></tbody>
  </table>
</div>
"""

DASHBOARD_JS = """
<script>
async function refreshStats() {
  const s = await api('/api/stats');
  $('#s-total').textContent = s.total;
  $('#s-get').textContent = s.get;
  $('#s-post').textContent = s.post;
  $('#s-find').textContent = s.findings;
  $('#s-mod').textContent = s.modified;
  $('#s-pend').textContent = s.pending;
  $('#intercept-status').textContent = s.intercept_enabled ? '● Intercept ON' : '○ Intercept OFF';
  $('#intercept-status').style.color = s.intercept_enabled ? 'var(--green)' : 'var(--text2)';
}
async function refreshLive() {
  const data = await api('/api/live');
  const tbody = $('#live-body');
  tbody.innerHTML = data.slice().reverse().map(c => `
    <tr>
      <td>${c.timestamp}</td>
      <td>${badgeMethod(c.method)}</td>
      <td title="${c.url}">${c.host}</td>
      <td class="${statusClass(c.status)}">${c.status}</td>
      <td>${c.size}</td>
      <td>${c.time}s</td>
      <td>${c.content_type||''}</td>
    </tr>`).join('') || '<tr><td colspan="7" class="empty">Aucune capture</td></tr>';
}
$('#btn-toggle').onclick = async () => {
  await api('/api/intercept/toggle', {method:'POST'});
  refreshStats();
};
$('#btn-clear').onclick = async () => {
  if (confirm('Vider tout l\\'historique et les findings ?')) {
    await api('/api/clear', {method:'POST'});
    refreshStats(); refreshLive();
  }
};
refreshStats(); refreshLive();
setInterval(refreshStats, 3000);
setInterval(refreshLive, 2000);
</script>
"""

INTERCEPT_CONTENT = """
<h1>⏸ Intercept</h1>
<div class="toolbar">
  <button class="btn btn-success" id="btn-forward-all">Forward All</button>
  <button class="btn btn-danger" id="btn-drop-all">Drop All</button>
  <span id="pend-count" style="color:var(--text2)"></span>
</div>
<div id="pending-list"></div>
"""

INTERCEPT_JS = """
<script>
async function loadPending() {
  const data = await api('/api/pending');
  $('#pend-count').textContent = data.length + ' en attente';
  const container = $('#pending-list');
  if (!data.length) {
    container.innerHTML = '<div class="empty">Aucune requête en attente</div>';
    return;
  }
  container.innerHTML = data.map(p => `
    <div class="panel" data-key="${p.key}">
      <div class="toolbar">
        <strong>${badgeMethod(p.method)} ${p.url}</strong>
        <button class="btn btn-success btn-sm" onclick="forward('${p.key}')">Forward</button>
        <button class="btn btn-danger btn-sm" onclick="drop('${p.key}')">Drop</button>
        <button class="btn btn-sm" onclick="toggleEdit(this)">Modifier</button>
      </div>
      <div class="edit-zone" style="display:none;margin-top:12px">
        <div class="form-row"><label>Méthode</label><input class="input edit-method" value="${p.method}"></div>
        <div class="form-row"><label>URL</label><input class="input edit-url" value="${p.url}"></div>
        <div class="form-row"><label>Headers</label><textarea class="edit-headers">${JSON.stringify(p.headers,null,2)}</textarea></div>
        <div class="form-row"><label>Body</label><textarea class="edit-body">${p.body||''}</textarea></div>
        <button class="btn btn-primary btn-sm" onclick="modify('${p.key}', this)">Appliquer & Forward</button>
      </div>
      <pre style="margin-top:8px;max-height:120px">${JSON.stringify(p.headers,null,2).slice(0,500)}</pre>
    </div>`).join('');
}
function toggleEdit(btn) {
  const zone = btn.closest('.panel').querySelector('.edit-zone');
  zone.style.display = zone.style.display === 'none' ? 'block' : 'none';
}
async function forward(key) {
  await api('/api/forward', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({key})});
  loadPending();
}
async function drop(key) {
  await api('/api/drop', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({key})});
  loadPending();
}
async function modify(key, btn) {
  const panel = btn.closest('.panel');
  let headers = {};
  try { headers = JSON.parse(panel.querySelector('.edit-headers').value); } catch(e) {}
  const mods = {
    method: panel.querySelector('.edit-method').value,
    url: panel.querySelector('.edit-url').value,
    headers: headers,
    body: panel.querySelector('.edit-body').value
  };
  await api('/api/modify', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({key, modifications:mods})});
  loadPending();
}
$('#btn-forward-all').onclick = async () => {
  const data = await api('/api/pending');
  for (const p of data) await forward(p.key);
};
$('#btn-drop-all').onclick = async () => {
  const data = await api('/api/pending');
  for (const p of data) await drop(p.key);
};
loadPending();
setInterval(loadPending, 1500);
</script>
"""

HISTORY_CONTENT = """
<h1>📜 History</h1>
<div class="toolbar">
  <input class="input" id="search" placeholder="Recherche (url, body...)" style="max-width:280px">
  <select id="filter-method" class="input" style="width:100px">
    <option value="">Méthode</option>
    <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
  </select>
  <select id="filter-status" class="input" style="width:100px">
    <option value="">Status</option>
    <option>200</option><option>301</option><option>302</option><option>400</option><option>401</option><option>403</option><option>404</option><option>500</option>
  </select>
  <input class="input" id="filter-host" placeholder="Host" style="max-width:160px">
  <button class="btn" id="btn-search">Filtrer</button>
</div>
<div class="split">
  <div class="panel" style="max-height:70vh;overflow-y:auto;padding:0">
    <table>
      <thead><tr><th>ID</th><th>Méthode</th><th>Host / Path</th><th>Status</th><th>Taille</th></tr></thead>
      <tbody id="hist-body"></tbody>
    </table>
  </div>
  <div class="panel" id="detail" style="max-height:70vh;overflow-y:auto">
    <div class="empty">Sélectionne une requête</div>
  </div>
</div>
"""

HISTORY_JS = """
<script>
async function loadHistory() {
  const q = new URLSearchParams({
    method: $('#filter-method').value,
    status: $('#filter-status').value,
    host: $('#filter-host').value,
    search: $('#search').value
  });
  const data = await api('/api/requests?' + q);
  $('#hist-body').innerHTML = data.map(r => `
    <tr style="cursor:pointer" onclick="showDetail(${r.id})">
      <td>${r.id}</td>
      <td>${badgeMethod(r.method)}</td>
      <td title="${r.host}${r.path}">${r.host}${r.path.length>40?r.path.slice(0,40)+'…':r.path}</td>
      <td class="${statusClass(r.status)}">${r.status||'—'}</td>
      <td>${r.size||0}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">Aucune requête</td></tr>';
}
async function showDetail(id) {
  const r = await api('/api/request/' + id);
  if (r.error) return;
  $('#detail').innerHTML = `
    <h2>${badgeMethod(r.method)} ${r.url}</h2>
    <p style="color:var(--text2);margin-bottom:12px">Status: <span class="${statusClass(r.status)}">${r.status}</span> · ${r.response_size} o · ${r.timestamp}</p>
    <div class="tabs">
      <div class="tab active" onclick="switchTab(this,'req')">Request</div>
      <div class="tab" onclick="switchTab(this,'resp')">Response</div>
    </div>
    <div id="tab-req">
      <h2>Headers</h2><pre>${JSON.stringify(r.headers,null,2)}</pre>
      <h2>Body</h2><pre>${r.body||'(vide)'}</pre>
      ${r.body_decoded && r.body_decoded.pretty ? '<h2>Decoded</h2><pre>'+r.body_decoded.pretty+'</pre>' : ''}
    </div>
    <div id="tab-resp" style="display:none">
      <h2>Headers</h2><pre>${JSON.stringify(r.response_headers,null,2)}</pre>
      <h2>Body</h2><pre>${(r.response_body||'(vide)').slice(0,8000)}</pre>
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button class="btn btn-sm" onclick="sendToRepeater(${r.id})">→ Repeater</button>
    </div>`;
}
function switchTab(el, which) {
  $$('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  $('#tab-req').style.display = which==='req' ? 'block' : 'none';
  $('#tab-resp').style.display = which==='resp' ? 'block' : 'none';
}
function sendToRepeater(id) {
  location.href = '/repeater?id=' + id;
}
$('#btn-search').onclick = loadHistory;
$('#search').oninput = debounce(loadHistory, 400);
loadHistory();
</script>
"""

INTRUDER_CONTENT = """
<h1>💣 Intruder</h1>
<div class="panel">
  <div class="form-row"><label>URL</label><input class="input" id="i-url" placeholder="https://target.com/page?id=§0§"></div>
  <div class="form-row"><label>Méthode</label>
    <select class="input" id="i-method" style="width:120px"><option>GET</option><option>POST</option><option>PUT</option></select>
  </div>
  <div class="form-row"><label>Headers</label><textarea id="i-headers" placeholder='{"Content-Type":"application/json"}'></textarea></div>
  <div class="form-row"><label>Body</label><textarea id="i-body" placeholder='{"id":"§0§"}'></textarea></div>
  <div class="form-row"><label>Payloads</label><textarea id="i-payloads" placeholder="un payload par ligne"></textarea></div>
  <div class="form-row"><label>Type</label>
    <select class="input" id="i-type" style="width:160px">
      <option value="sniper">Sniper</option>
      <option value="battering_ram">Battering Ram</option>
      <option value="pitchfork">Pitchfork</option>
      <option value="cluster_bomb">Cluster Bomb</option>
    </select>
  </div>
  <div class="form-row"><label>Threads</label><input class="input" id="i-threads" type="number" value="5" style="width:80px"></div>
  <div class="toolbar">
    <button class="btn btn-primary" id="btn-start">▶ Start</button>
    <button class="btn btn-danger" id="btn-stop">⏹ Stop</button>
    <span id="i-progress" style="color:var(--text2)"></span>
  </div>
</div>
<div class="panel" style="max-height:400px;overflow-y:auto;padding:0">
  <table>
    <thead><tr><th>#</th><th>Payloads</th><th>Status</th><th>Taille</th><th>Temps</th></tr></thead>
    <tbody id="i-results"></tbody>
  </table>
</div>
"""

INTRUDER_JS = """
<script>
$('#btn-start').onclick = async () => {
  let headers = {};
  try { headers = JSON.parse($('#i-headers').value || '{}'); } catch(e) {}
  const payloads = $('#i-payloads').value.split('\\n').map(l => l.trim()).filter(Boolean);
  await api('/api/intruder/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      url: $('#i-url').value,
      method: $('#i-method').value,
      headers, body: $('#i-body').value,
      payloads, attack_type: $('#i-type').value,
      threads: parseInt($('#i-threads').value) || 5
    })
  });
};
$('#btn-stop').onclick = () => api('/api/intruder/stop', {method:'POST'});
async function pollIntruder() {
  const s = await api('/api/intruder/status');
  $('#i-progress').textContent = s.running
    ? `En cours ${s.progress.current}/${s.progress.total}`
    : (s.progress.total ? `Terminé ${s.progress.current}/${s.progress.total}` : '');
  $('#i-results').innerHTML = (s.results||[]).slice().reverse().map(r => `
    <tr>
      <td>${r.idx}</td>
      <td>${(r.payloads||[]).join(' | ')}</td>
      <td class="${statusClass(r.status)}">${r.status||r.error||'—'}</td>
      <td>${r.size||0}</td>
      <td>${r.time||0}s</td>
    </tr>`).join('');
}
setInterval(pollIntruder, 1500);
</script>
"""

SCANNER_CONTENT = """
<h1>🔍 Scanner (passif)</h1>
<div class="panel" style="max-height:75vh;overflow-y:auto;padding:0">
  <table>
    <thead><tr><th>Sévérité</th><th>Type</th><th>URL</th><th>Description</th><th>Date</th></tr></thead>
    <tbody id="find-body"></tbody>
  </table>
</div>
"""

SCANNER_JS = """
<script>
async function loadFindings() {
  const data = await api('/api/findings');
  $('#find-body').innerHTML = data.map(f => `
    <tr>
      <td><span class="badge sev-${f.severity}">${f.severity}</span></td>
      <td>${f.type}</td>
      <td title="${f.url}">${f.url.length>60?f.url.slice(0,60)+'…':f.url}</td>
      <td>${f.description}</td>
      <td>${(f.timestamp||'').slice(0,19)}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">Aucun finding</td></tr>';
}
loadFindings();
setInterval(loadFindings, 5000);
</script>
"""

REPEATER_CONTENT = """
<h1>🔁 Repeater</h1>
<div class="split">
  <div class="panel">
    <div class="form-row"><label>Méthode</label>
      <select class="input" id="r-method" style="width:120px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select>
    </div>
    <div class="form-row"><label>URL</label><input class="input" id="r-url" placeholder="https://..."></div>
    <div class="form-row"><label>Headers</label><textarea id="r-headers" placeholder='{"User-Agent":"Burp-Like"}'></textarea></div>
    <div class="form-row"><label>Body</label><textarea id="r-body"></textarea></div>
    <button class="btn btn-primary" id="btn-send">Envoyer</button>
  </div>
  <div class="panel" id="r-response">
    <div class="empty">Réponse ici</div>
  </div>
</div>
"""

REPEATER_JS = """
<script>
$('#btn-send').onclick = async () => {
  let headers = {};
  try { headers = JSON.parse($('#r-headers').value || '{}'); } catch(e) {}
  const res = await api('/api/repeater/send', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      method: $('#r-method').value,
      url: $('#r-url').value,
      headers, body: $('#r-body').value
    })
  });
  if (res.error) {
    $('#r-response').innerHTML = `<div style="color:var(--red)">${res.error}</div>`;
    return;
  }
  $('#r-response').innerHTML = `
    <p>Status: <span class="${statusClass(res.status)}">${res.status}</span> · ${res.size} o · ${res.time}s</p>
    <h2>Headers</h2><pre>${JSON.stringify(res.headers,null,2)}</pre>
    <h2>Body</h2><pre>${(res.body||'').slice(0,10000)}</pre>`;
};
const params = new URLSearchParams(location.search);
if (params.get('id')) {
  api('/api/request/' + params.get('id')).then(r => {
    if (r.error) return;
    $('#r-method').value = r.method;
    $('#r-url').value = r.url;
    $('#r-headers').value = JSON.stringify(r.headers, null, 2);
    $('#r-body').value = r.body || '';
  });
}
</script>
"""

DECODER_CONTENT = """
<h1>🔓 Decoder</h1>
<div class="split">
  <div class="panel">
    <textarea id="d-input" placeholder="Colle le texte à encoder / décoder..." style="min-height:200px"></textarea>
    <div class="toolbar" style="margin-top:12px;flex-wrap:wrap">
      <button class="btn btn-sm" data-act="url_encode">URL Encode</button>
      <button class="btn btn-sm" data-act="url_decode">URL Decode</button>
      <button class="btn btn-sm" data-act="b64_encode">B64 Encode</button>
      <button class="btn btn-sm" data-act="b64_decode">B64 Decode</button>
      <button class="btn btn-sm" data-act="hex_encode">Hex Encode</button>
      <button class="btn btn-sm" data-act="hex_decode">Hex Decode</button>
      <button class="btn btn-sm" data-act="html_encode">HTML Encode</button>
      <button class="btn btn-sm" data-act="html_decode">HTML Decode</button>
      <button class="btn btn-sm" data-act="jwt_decode">JWT Decode</button>
      <button class="btn btn-sm" data-act="md5">MD5</button>
      <button class="btn btn-sm" data-act="sha1">SHA1</button>
      <button class="btn btn-sm" data-act="sha256">SHA256</button>
      <button class="btn btn-primary btn-sm" data-act="auto">Auto</button>
    </div>
  </div>
  <div class="panel">
    <pre id="d-output" style="min-height:200px">(résultat)</pre>
  </div>
</div>
"""

DECODER_JS = """
<script>
$$('[data-act]').forEach(btn => {
  btn.onclick = async () => {
    const res = await api('/api/decode', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ text: $('#d-input').value, action: btn.dataset.act })
    });
    $('#d-output').textContent = res.error || res.result;
  };
});
</script>
"""


def render_page(title, page, content, extra_js=""):
    return render_template_string(
        LAYOUT,
        title=title,
        page=page,
        content=content,
        extra_js=extra_js
    )


# ==================== FLASK APP ====================

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def dashboard():
    return render_page("Dashboard", "dashboard", DASHBOARD_CONTENT, DASHBOARD_JS)


@app.route("/intercept")
def intercept_page():
    return render_page("Intercept", "intercept", INTERCEPT_CONTENT, INTERCEPT_JS)


@app.route("/history")
def history_page():
    return render_page("History", "history", HISTORY_CONTENT, HISTORY_JS)


@app.route("/intruder")
def intruder_page():
    return render_page("Intruder", "intruder", INTRUDER_CONTENT, INTRUDER_JS)


@app.route("/scanner")
def scanner_page():
    return render_page("Scanner", "scanner", SCANNER_CONTENT, SCANNER_JS)


@app.route("/repeater")
def repeater_page():
    return render_page("Repeater", "repeater", REPEATER_CONTENT, REPEATER_JS)


@app.route("/decoder")
def decoder_page():
    return render_page("Decoder", "decoder", DECODER_CONTENT, DECODER_JS)


@app.route("/api/stats")
def api_stats():
    stats = db.stats()
    stats["intercept_enabled"] = signal_bus.intercept_enabled
    stats["pending"] = len(signal_bus.get_pending())
    return jsonify(stats)


@app.route("/api/live")
def api_live():
    return jsonify(signal_bus.get_live_captures(50))


@app.route("/api/requests")
def api_requests():
    method = request.args.get("method", "")
    status = request.args.get("status", "")
    host = request.args.get("host", "")
    search = request.args.get("search", "")
    rows = db.search(method, status, host, search)
    return jsonify([
        {
            "id": r[0], "method": r[1], "host": r[2], "path": r[3],
            "status": r[4], "size": r[5], "timestamp": r[6],
            "content_type": r[7], "modified": r[8] == 1,
        } for r in rows
    ])


@app.route("/api/request/<int:req_id>")
def api_request_detail(req_id):
    row = db.get_by_id(req_id)
    if not row:
        return jsonify({"error": "not found"}), 404

    # 0id 1method 2url 3host 4path 5headers 6body 7status
    # 8resp_headers 9resp_body 10timestamp 11modified 12resp_size
    # 13ct_req 14ct_resp 15decoded_body
    try:
        headers = json.loads(row[5] or "{}")
    except Exception:
        headers = {}
    try:
        resp_headers = json.loads(row[8] or "{}")
    except Exception:
        resp_headers = {}
    try:
        decoded_body = json.loads(row[15] or "{}")
    except Exception:
        decoded_body = Decoder.decode_body(row[6] or "")

    resp_body = row[9] or ""
    decoded_resp = Decoder.decode_body(resp_body, row[14] or "")

    return jsonify({
        "id": row[0],
        "method": row[1],
        "url": row[2],
        "host": row[3],
        "path": row[4],
        "headers": headers,
        "body": row[6],
        "body_decoded": decoded_body,
        "body_kind": content_kind(row[13] or "", row[6] or ""),
        "status": row[7],
        "response_headers": resp_headers,
        "response_body": resp_body,
        "response_decoded": decoded_resp,
        "response_kind": content_kind(row[14] or "", resp_body),
        "timestamp": row[10],
        "modified": row[11] == 1,
        "response_size": row[12] or len(resp_body),
    })


@app.route("/api/pending")
def api_pending():
    pending = signal_bus.get_pending()
    result = []
    for p in pending:
        data = p["data"]
        result.append({
            "key": p["key"],
            "method": data.get("method", ""),
            "url": data.get("url", ""),
            "host": data.get("host", ""),
            "path": data.get("path", ""),
            "headers": data.get("headers", {}),
            "body": data.get("body", ""),
            "body_decoded": data.get("decoded_body", {}),
            "content_type": data.get("content_type_req", ""),
        })
    return jsonify(result)


@app.route("/api/intercept/toggle", methods=["POST"])
def api_toggle_intercept():
    signal_bus.intercept_enabled = not signal_bus.intercept_enabled
    return jsonify({"enabled": signal_bus.intercept_enabled})


@app.route("/api/forward", methods=["POST"])
def api_forward():
    data = request.get_json() or {}
    key = data.get("key")
    if not key:
        return jsonify({"error": "no key"}), 400
    signal_bus.apply_modification(key, {})
    return jsonify({"ok": True})


@app.route("/api/drop", methods=["POST"])
def api_drop():
    data = request.get_json() or {}
    key = data.get("key")
    if not key:
        return jsonify({"error": "no key"}), 400
    signal_bus.apply_modification(key, {"drop": True})
    return jsonify({"ok": True})


@app.route("/api/modify", methods=["POST"])
def api_modify():
    data = request.get_json() or {}
    key = data.get("key")
    modifications = data.get("modifications", {})
    if not key:
        return jsonify({"error": "no key"}), 400
    signal_bus.apply_modification(key, modifications)
    return jsonify({"ok": True})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear()
    return jsonify({"ok": True})


@app.route("/api/findings")
def api_findings():
    rows = db.get_findings()
    return jsonify([
        {
            "id": r[0], "severity": r[1], "type": r[2],
            "url": r[3], "description": r[4],
            "evidence": r[5], "timestamp": r[6],
        } for r in rows
    ])


@app.route("/api/decode", methods=["POST"])
def api_decode():
    data = request.get_json() or {}
    text = data.get("text", "")
    action = data.get("action", "auto")

    try:
        if action == "url_encode":
            result = urllib.parse.quote(text)
        elif action == "url_decode":
            result = urllib.parse.unquote(text)
        elif action == "b64_encode":
            result = base64.b64encode(text.encode()).decode()
        elif action == "b64_decode":
            result = base64.b64decode(text.encode()).decode()
        elif action == "hex_encode":
            result = text.encode().hex()
        elif action == "hex_decode":
            result = bytes.fromhex(text).decode()
        elif action == "html_encode":
            result = html_lib.escape(text)
        elif action == "html_decode":
            result = html_lib.unescape(text)
        elif action == "jwt_decode":
            parts = text.split(".")
            if len(parts) == 3:
                pad = lambda s: s + "=" * (-len(s) % 4)
                h = base64.urlsafe_b64decode(pad(parts[0])).decode("utf-8", errors="ignore")
                p = base64.urlsafe_b64decode(pad(parts[1])).decode("utf-8", errors="ignore")
                try:
                    h = json.dumps(json.loads(h), indent=2)
                    p = json.dumps(json.loads(p), indent=2)
                except Exception:
                    pass
                result = f"Header:\n{h}\n\nPayload:\n{p}"
            else:
                result = "JWT invalide (3 parties attendues)"
        elif action == "md5":
            result = hashlib.md5(text.encode()).hexdigest()
        elif action == "sha1":
            result = hashlib.sha1(text.encode()).hexdigest()
        elif action == "sha256":
            result = hashlib.sha256(text.encode()).hexdigest()
        elif action == "auto":
            decoded = Decoder.decode_value(text)
            result = decoded["decoded"]
        else:
            result = "Action inconnue"
        return jsonify({"result": result, "error": None})
    except Exception as e:
        return jsonify({"result": None, "error": str(e)})


@app.route("/api/repeater/send", methods=["POST"])
def api_repeater_send():
    data = request.get_json() or {}
    method = data.get("method", "GET")
    url = data.get("url", "")
    headers = data.get("headers", {})
    body = data.get("body", "")

    if not url or not REQUESTS_OK:
        return jsonify({"error": "URL manquante ou requests non installé"}), 400

    try:
        url = url.strip().replace("\n", "").replace("\r", "")
        r = requests.request(
            method, url,
            headers=headers,
            data=body.encode() if body else None,
            timeout=30, verify=False, allow_redirects=False,
        )
        decoded = Decoder.decode_body(r.text, r.headers.get("Content-Type", ""))
        response_data = {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": r.text,
            "body_decoded": decoded,
            "body_kind": content_kind(r.headers.get("Content-Type", ""), r.text),
            "size": len(r.content),
            "time": r.elapsed.total_seconds(),
        }
        db.insert({
            "method": method, "url": url,
            "host": urllib.parse.urlparse(url).netloc,
            "path": urllib.parse.urlparse(url).path,
            "headers": headers, "body": body,
            "status": r.status_code,
            "response_headers": dict(r.headers),
            "response_body": r.text,
            "response_size": len(r.content),
            "content_type_req": headers.get("Content-Type", ""),
            "content_type_resp": r.headers.get("Content-Type", ""),
            "decoded_body": Decoder.decode_body(body, headers.get("Content-Type", "")),
        })
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/json")
def api_export_json():
    data = db.export_json()
    return Response(
        json.dumps(data, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment;filename=burp_like_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
    )


@app.route("/api/export/html")
def api_export_html():
    requests_data = db.export_json()
    findings = db.get_findings()
    sev_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8844", "MEDIUM": "#ffcc44", "LOW": "#8888ff"}
    html_content = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Burp-Like Report</title>
<style>
body {{ font-family: 'Consolas', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
h1, h2 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 8px; border-bottom: 1px solid #30363d; text-align: left; font-size: 13px; }}
th {{ background: #161b22; color: #7ee787; }}
.badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 11px; }}
</style></head><body>
<h1>🔷 Burp-Like Web — Rapport</h1>
<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total requêtes: {len(requests_data)} — Findings: {len(findings)}</p>
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Sévérité</th><th>Type</th><th>URL</th><th>Description</th></tr>"""
    for f in findings:
        sev = f[1]
        color = sev_colors.get(sev, "#888")
        html_content += f'<tr><td><span class="badge" style="background:{color}">{sev}</span></td>'
        html_content += f"<td>{f[2]}</td><td>{f[3][:100]}</td><td>{f[4]}</td></tr>"
    html_content += "</table><h2>Historique</h2>"
    html_content += "<table><tr><th>ID</th><th>Method</th><th>URL</th><th>Status</th></tr>"
    for r in requests_data[:500]:
        html_content += f'<tr><td>{r.get("id")}</td><td>{r.get("method")}</td><td>{r.get("url","")[:120]}</td><td>{r.get("status")}</td></tr>'
    html_content += "</table></body></html>"
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment;filename=burp_like_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'}
    )


# ==================== INTRUDER ====================

intruder_state = {
    "running": False,
    "progress": {"current": 0, "total": 0},
    "results": [],
    "lock": threading.Lock(),
    "stop_flag": False,
}


def run_intruder(config):
    url = config["url"]
    method = config["method"]
    headers = config.get("headers") or {}
    body = config.get("body") or ""
    payloads = config.get("payloads") or []
    attack_type = config.get("attack_type", "sniper")
    threads = config.get("threads", 5)

    all_text = url + body + json.dumps(headers)
    positions = len(re.findall(r"§\d+§", all_text))
    if positions == 0:
        positions = 1

    if attack_type == "sniper":
        combos = []
        for pos in range(positions):
            for p in payloads:
                combo = [""] * positions
                combo[pos] = p
                combos.append(combo)
    elif attack_type == "battering_ram":
        combos = [[p] * positions for p in payloads]
    elif attack_type == "pitchfork":
        if payloads and isinstance(payloads[0], list):
            combos = [list(c) for c in zip(*payloads)]
        else:
            combos = [[p] for p in payloads]
    elif attack_type == "cluster_bomb":
        import itertools
        if payloads and isinstance(payloads[0], list):
            combos = [list(c) for c in itertools.product(*payloads)]
        else:
            combos = [list(c) for c in itertools.product(payloads, repeat=positions)]
    else:
        combos = []

    with intruder_state["lock"]:
        intruder_state["progress"] = {"current": 0, "total": len(combos)}
        intruder_state["results"] = []
        intruder_state["running"] = True
        intruder_state["stop_flag"] = False

    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.3)))

    def send_one(idx, combo):
        if intruder_state["stop_flag"]:
            return None
        try:
            final_url = url
            final_body = body
            final_headers = dict(headers)
            for pos_idx, payload in enumerate(combo):
                ph = f"§{pos_idx}§"
                final_url = final_url.replace(ph, payload)
                final_body = final_body.replace(ph, payload)
                for k in list(final_headers.keys()):
                    final_headers[k] = str(final_headers[k]).replace(ph, payload)

            start = time.time()
            r = session.request(
                method, final_url, headers=final_headers,
                data=final_body.encode() if final_body else None,
                timeout=12, allow_redirects=False, verify=False,
            )
            elapsed = time.time() - start
            return {
                "idx": idx, "payloads": combo,
                "status": r.status_code, "size": len(r.content),
                "time": round(elapsed, 3),
                "body": r.text[:200],
            }
        except Exception as e:
            return {"idx": idx, "payloads": combo, "error": str(e),
                    "status": 0, "size": 0, "time": 0, "body": ""}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(send_one, i, c): i for i, c in enumerate(combos)}
        for i, fut in enumerate(as_completed(futures)):
            if intruder_state["stop_flag"]:
                break
            result = fut.result()
            if result:
                with intruder_state["lock"]:
                    intruder_state["results"].append(result)
                    intruder_state["progress"]["current"] = len(intruder_state["results"])

    with intruder_state["lock"]:
        intruder_state["running"] = False


@app.route("/api/intruder/start", methods=["POST"])
def api_intruder_start():
    if intruder_state["running"]:
        return jsonify({"error": "Intruder déjà en cours"}), 400
    config = request.get_json() or {}
    threading.Thread(target=run_intruder, args=(config,), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/intruder/stop", methods=["POST"])
def api_intruder_stop():
    intruder_state["stop_flag"] = True
    return jsonify({"ok": True})


@app.route("/api/intruder/status")
def api_intruder_status():
    with intruder_state["lock"]:
        return jsonify({
            "running": intruder_state["running"],
            "progress": intruder_state["progress"],
            "results": intruder_state["results"][-80:],
        })


# ==================== MAIN ====================

def run_web():
    ips = get_local_ips()
    primary = ips[0]
    extra = " | ".join(ips[1:]) if len(ips) > 1 else "—"

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔷 BURP-LIKE WEB v2.2 — JATHNIEL EDITION                   ║
║                                                              ║
║   Interface web :                                            ║
║     → http://127.0.0.1:{WEB_PORT}          (depuis WSL)              ║
║     → http://{primary}:{WEB_PORT}    (depuis Windows)            ║
║                                                              ║
║   Proxy MITM    :                                            ║
║     → 127.0.0.1:{PROXY_PORT}             (depuis WSL)              ║
║     → {primary}:{PROXY_PORT}         (depuis Windows)            ║
║                                                              ║
║   Certificat    : ~/.mitmproxy/mitmproxy-ca-cert.pem         ║
║   Autres IPs    : {extra}                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(
        host="0.0.0.0", port=WEB_PORT,
        debug=False, use_reloader=False,
        threaded=True,
    )


def main():
    proxy = ProxyServer(port=PROXY_PORT)
    proxy.start()
    proxy.ready.wait(timeout=5)
    try:
        run_web()
    except KeyboardInterrupt:
        print("\n[!] Arrêt...")
        proxy.shutdown()


if __name__ == "__main__":
    main()