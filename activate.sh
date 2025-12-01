#!/bin/bash
# Quick activation script for dnsintel

cd "$(dirname "$0")"
source venv/bin/activate
echo "✅ DNSIntel virtual environment activated!"
echo ""
echo "Available commands:"
echo "  dnsintel mx <domain>           - Check MX records"
echo "  dnsintel mx <domain> --full    - Full email config"
echo "  dnsintel dns <domain> -t MX    - DNS lookup for MX"
echo "  dnsintel whois <domain>        - WHOIS lookup"
echo "  dnsintel ssl <domain>          - SSL check"
echo "  dnsintel verify <domain>       - Full verification"
echo "  dnsintel all <domain>          - Complete report"
echo ""
echo "Try: dnsintel mx dtdc.com --full"
echo ""

