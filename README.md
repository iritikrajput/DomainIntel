# DomainIntel

A comprehensive domain intelligence and reconnaissance tool for security professionals and system administrators.

## Features

- **DNS Lookup** - Query various DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)
- **MX Records Check** - Dedicated mail server verification with SPF and DMARC analysis
- **WHOIS Lookup** - Retrieve domain registration and ownership information
- **SSL Certificate Checker** - Analyze SSL/TLS certificates and expiration dates
- **IP Geolocation** - Get geographic and network information about IP addresses
- **Domain Verification** - Validate domain configurations and security settings

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/yourusername/domainintel.git
cd domainintel

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package
pip install -e .
```

### Quick Activation

After installation, use the activation script:

```bash
source activate.sh
```

## Usage

### Command Line Interface

```bash
# DNS lookup (various record types)
domainintel dns example.com           # A records (default)
domainintel dns example.com -t MX     # MX records
domainintel dns example.com -t TXT    # TXT records
domainintel dns example.com -t ALL    # All record types

# MX records check
domainintel mx example.com            # Quick MX check
domainintel mx example.com --full     # Full email config (MX + SPF + DMARC)

# WHOIS lookup
domainintel whois example.com

# SSL certificate check
domainintel ssl example.com
domainintel ssl example.com -p 8443   # Custom port

# IP information
domainintel ip 8.8.8.8

# Domain verification (comprehensive check)
domainintel verify example.com

# Complete intelligence report
domainintel all example.com
```

### Python API

```python
from domainintel.core import dns_lookup, whois_lookup, ssl_checker, ip_info, verifier

# DNS lookup
results = dns_lookup.query_domain("example.com", record_type="A")
print(results['records'])

# MX records
mx_records = dns_lookup.get_mx_records("example.com")
for mx in mx_records:
    print(f"Priority {mx['priority']}: {mx['exchange']}")

# Full email configuration check
config = dns_lookup.check_mail_configuration("example.com")
print(f"Has mail: {config['has_mail']}")
print(f"SPF: {config['spf_record']}")
print(f"DMARC: {config['dmarc_record']}")

# WHOIS lookup
whois_info = whois_lookup.get_whois("example.com")

# SSL certificate check
ssl_info = ssl_checker.check_certificate("example.com")

# IP information
ip_data = ip_info.get_ip_info("8.8.8.8")

# Domain verification
verification = verifier.verify_domain("example.com")
```

## Project Structure

```
domainintel-project/
├── pyproject.toml          # Project configuration
├── setup.cfg               # Setup configuration
├── requirements.txt        # Dependencies
├── README.md               # Documentation
├── LICENSE                 # MIT License
├── activate.sh             # Quick activation script
├── domainintel/            # Main package
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── core/               # Core functionality
│   │   ├── __init__.py
│   │   ├── dns_lookup.py   # DNS queries
│   │   ├── whois_lookup.py # WHOIS queries
│   │   ├── ssl_checker.py  # SSL certificate checks
│   │   ├── ip_info.py      # IP geolocation
│   │   └── verifier.py     # Domain verification
│   ├── utils/              # Utilities
│   │   ├── __init__.py
│   │   ├── output.py       # Output formatting
│   │   └── validators.py   # Input validation
│   └── data/
│       └── example_rules.json
└── tests/
    └── test_basic.py       # Unit tests
```

## Requirements

- Python 3.8 or higher
- dnspython
- python-whois
- cryptography
- requests
- colorama
- tabulate

## Development

### Setup Development Environment

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v
```

### Code Formatting

```bash
black domainintel/
flake8 domainintel/
```

## Examples

### Check Email Configuration

```bash
$ domainintel mx gmail.com --full

============================================================
MX Records Check: gmail.com
============================================================

MX Records Found:
  1. Priority:   5 → gmail-smtp-in.l.google.com
  2. Priority:  10 → alt1.gmail-smtp-in.l.google.com
  ...

SPF Record:
  v=spf1 include:_spf.google.com ~all

DMARC Record:
  v=DMARC1; p=none; rua=mailto:...

✓ Email configuration looks good!
```

### Domain Verification

```bash
$ domainintel verify example.com

Domain Verification Report: example.com

Total Checks: 7
Passed: 5
Failed: 0
Warnings: 2

DNS Resolution:
  ✓ Domain resolves to 1 IP address(es)

MX Records:
  ✓ Domain has 1 MX record(s) configured

SSL Certificate:
  ✓ Valid SSL certificate

Overall Score: 71.4%
Good domain configuration with some improvements needed
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This tool is intended for legitimate security research and system administration purposes only. Always obtain proper authorization before scanning domains or networks you do not own.

## Author

Your Name - netscafeeee@gmail.com

## Acknowledgments

- [dnspython](https://www.dnspython.org/) - DNS toolkit for Python
- [python-whois](https://pypi.org/project/python-whois/) - WHOIS lookup library
- [colorama](https://pypi.org/project/colorama/) - Cross-platform colored terminal text
# DomainIntel
