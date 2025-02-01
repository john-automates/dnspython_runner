print("[+] START: DNS Analysis Tool")

import sys
import os
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    print("[+] DNS modules imported successfully")
except ImportError as e:
    print(f"[ERROR] Failed to import required DNS modules: {str(e)}")
    sys.exit(1)


def get_dns_records(domain, record_type='A'):
    print(f"[~] Resolving {record_type} records for: {domain}")
    try:
        answers = dns.resolver.resolve(domain, record_type)
        print(f"[+] Resolution for {record_type} successful")
        return [str(rdata) for rdata in answers]
    except Exception as e:
        print(f"[ERROR] Failed to resolve {record_type} for {domain}: {str(e)}")
        return [f"Error: {str(e)}"]


def get_reverse_dns(ip_address):
    print(f"[~] Performing reverse DNS lookup for: {ip_address}")
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        print("[+] Reverse resolution successful")
        return [str(rdata) for rdata in answers]
    except Exception as e:
        print(f"[ERROR] Reverse DNS lookup failed for {ip_address}: {str(e)}")
        return [f"Error: {str(e)}"]


def generate_dns_report(domain):
    print("[~] Generating DNS report...")
    
    # Dictionary of record types and their descriptions
    record_types = {
        'A': 'IPv4 Addresses',
        'AAAA': 'IPv6 Addresses',
        'MX': 'Mail Servers',
        'NS': 'Name Servers',
        'TXT': 'Text Records',
        'SOA': 'Start of Authority',
        'CAA': 'Certificate Authority Authorization',
        'CNAME': 'Canonical Names',
        'SRV': 'Service Records',
    }

    print("\n" + "=" * 60)
    print(f"[+] DNS REPORT FOR: {domain}")
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[DEBUG] Report generated at: {current_time}")
    print("=" * 60)

    # Process each record type
    for record_type, description in record_types.items():
        records = get_dns_records(domain, record_type)
        print(f"\n[~] {description} ({record_type} Records):")
        print("-" * 40)
        if records and not (len(records) == 1 and records[0].startswith('Error')):
            for record in records:
                print(f"  {record}")
        else:
            print("  No records found or error occurred")

    # Reverse DNS lookups for A records
    a_records = get_dns_records(domain, 'A')
    if a_records and not (len(a_records) == 1 and a_records[0].startswith('Error')):
        print("\n[~] Reverse DNS Lookups for A records:")
        print("-" * 40)
        for ip in a_records:
            hostnames = get_reverse_dns(ip)
            print(f"  {ip}:")
            for hostname in hostnames:
                print(f"    → {hostname}")

    print("\n" + "=" * 60)
    print("[+] END OF REPORT")
    print("=" * 60)


def main():
    print("[~] Checking command line arguments...")
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(f"[DEBUG] Domain provided via arguments: {domain}")
    else:
        domain = "google.com"
        print("[DEBUG] No domain provided, defaulting to google.com")
    generate_dns_report(domain)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
        sys.exit(1)

print("[+] END: DNS Analysis Tool")