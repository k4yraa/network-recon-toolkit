![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

# Network Recon Toolkit
A passive reconnaissance tool for collecting basic information about a target, including DNS, HTTP, TLS and WHOIS data.

## Overview
This tool performs passive reconnaissance without direct interaction with the target infrastructure.

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

## Example Output
Target: github.com

IP: 140.82.x.x
Location: Germany
Server: GitHub

Response Time: 120ms

Security Headers:

Strict-Transport-Security

Content-Security-Policy

DNS:

MX: ...

TXT: ...

# Disclaimer

This tool is intended for educational purposes and authorized testing only.
Do not use it against systems without permission. The user is responsible for any misuse.

# Notes

Results may vary depending on network conditions and target configuration

Some data sources rely on external services


## Installation

```bash
git clone https://github.com/k4yraa/network-recon-toolkit.git
cd network-recon-toolkit
pip install -r requirements.txt

USAGE
python main.py github.com
python main.py https://example.com --json
python main.py example.com --output report.json
