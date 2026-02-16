# 🔓 Access Control Bypass Tester

A powerful Python tool for testing access control vulnerabilities through 140+ bypass techniques including path manipulation, header injection, HTTP verb tampering, and protocol confusion attacks.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 🎯 Features

- **140+ Bypass Techniques**: Path traversal, encoding tricks, header manipulation
- **Multi-threaded**: Fast concurrent testing (configurable threads)
- **Custom Headers**: Add your own authentication/API headers
- **Header Combinations**: Test multiple headers together for complex bypasses
- **HTTP Verb Tampering**: Automatic method switching (GET→HEAD, POST→PUT, etc.)
- **Body-Based Bypasses**: JSON payload testing for POST/PUT/PATCH requests
- **Smart Detection**: Identifies IP spoofing, URL rewrite, and method override bypasses
- **Comprehensive Logging**: Detailed output with success tracking

## 📥 Installation

```bash
# Clone the repository
git clone [https://github.com/yourusername/bypass-tester.git](https://github.com/ShakhYou/401_403_bypasser.git)
cd bypass-tester

# Install dependencies
pip install requests

# Run the tool
python3 bypass_tester.py -u https://target.com/admin
```

## 🚀 Quick Start

### Basic Usage
```bash
python3 bypass_tester.py -u https://api.example.com/admin
```

### With Custom Headers
```bash
python3 bypass_tester.py -u https://api.example.com/admin \
    -H "Authorization: Bearer token123" \
    -H "X-API-Key: secret"
```

### Fast Scan (More Threads)
```bash
python3 bypass_tester.py -u https://example.com/api -t 20
```

### Verbose Output
```bash
python3 bypass_tester.py -u https://example.com/admin -v
```

## 📖 Usage

```
usage: bypass_tester.py [-h] -u URL [-H HEADERS] [-t THREADS] [--timeout TIMEOUT] [-v]

Access Control Bypass Testing Tool

options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL to test (required)
  -H HEADERS, --header HEADERS
                        Custom header (format: 'Key: Value'). Can be used multiple times
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  -v, --verbose         Verbose output - show all requests
```

## 🔥 Bypass Techniques

### Path Manipulation
- Path traversal (`/admin/../admin`, `/admin/..;/`)
- Encoding variations (`/%61dmin`, `%252fadmin`)
- Case mutations (`/Admin`, `/ADMIN`)
- Unicode normalization

### Header-Based Bypasses
- IP Spoofing (`X-Forwarded-For: 127.0.0.1`)
- URL Rewriting (`X-Original-URL: /admin`)
- Method Override (`X-HTTP-Method-Override: GET`)
- Multi-header combinations

### HTTP Method Tampering
- Verb switching (GET→HEAD, POST→PUT)
- Method tunneling via headers
- TRACE, CONNECT testing

### Advanced Techniques
- HTTP request smuggling patterns
- Protocol confusion attacks
- Body-based bypasses (JSON payloads)
- Cache poisoning headers
- CDN-specific bypasses

## 📊 Example Output

```
[*] Target: https://api.example.com/admin
[*] Threads: 10
[*] Testing 350 path variations × 9 methods
────────────────────────────────────────────────────────────────────────────────
METHOD   | CODE  | LENGTH   | PATH
────────────────────────────────────────────────────────────────────────────────
GET      | 403   | 1234     | /admin
GET      | 200   | 5678     | /admin/
  [!] BYPASS: X-Forwarded-For: 127.0.0.1 → 200
  [!!] COMBO BYPASS: X-Real-IP: 127.0.0.1, X-Forwarded-Proto: https → 200
HEAD     | 200   | 0        | /admin
  [!] VERB TAMPERING: GET → HEAD → 200

════════════════════════════════════════════════════════════════════════════════
                              BYPASS SUMMARY
════════════════════════════════════════════════════════════════════════════════
[+] Found 3 potential bypass(es):

  1. SUCCESS: GET /admin/ (Status: 200)
  2. HEADER BYPASS: GET /admin via X-Forwarded-For: 127.0.0.1 (Status: 200)
  3. VERB TAMPERING: /admin GET→HEAD (Status: 200)
════════════════════════════════════════════════════════════════════════════════
```

## 🎓 Real-World Examples

### Test Admin Panel
```bash
python3 bypass_tester.py -u https://example.com/admin -t 15
```

### Test API Endpoint with Authentication
```bash
python3 bypass_tester.py -u https://api.example.com/users \
    -H "Authorization: Bearer eyJ..." \
    -H "X-API-Key: abc123" \
    -t 10
```

### Stealth Mode (Slow, Avoid Detection)
```bash
python3 bypass_tester.py -u https://target.com/internal \
    -t 3 --timeout 10
```

## 🔧 Requirements

- Python 3.7+
- `requests` library

```bash
pip install requests
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
