![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

# Network Recon Toolkit
A passive reconnaissance tool for collecting basic information about a target, including DNS, HTTP, TLS and WHOIS data.

## Features
- Domain, IP or URL input
- DNS resolution and reverse lookup
- TXT / MX / NS record queries
- HTTP inspection and response analysis
- Response time measurement
- Redirect chain detection
- Security header overview
- TLS certificate summary
- WHOIS information
- JSON output support
  
# Disclaimer

This tool is intended for educational purposes and authorized testing only.
Do not use it against systems without permission. The user is responsible for any misuse.

# Notes

Results may vary depending on network conditions and target configuration

Some data sources rely on external services

## Usage
```bash
python main.py github.com
python main.py https://example.com --json
python main.py example.com --output report.json

