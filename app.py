import dns.resolver
import dns.reversename
from datetime import datetime

def get_dns_records(domain, record_type='A'):
    """
    Look up DNS records for a given domain and record type.
    Returns a list of records or None if lookup fails.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        return [f"Error: {str(e)}"]

def get_reverse_dns(ip_address):
    """
    Perform a reverse DNS lookup for an IP address.
    Returns hostname or error message.
    """
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        return [str(rdata) for rdata in answers]
    except Exception as e:
        return [f"Error: {str(e)}"]

def generate_dns_report(domain):
    """
    Generate a comprehensive DNS report for a domain.
    """
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

    print("\n" + "="*60)
    print(f"DNS REPORT FOR: {domain}")
    print(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # Get all DNS records
    for record_type, description in record_types.items():
        records = get_dns_records(domain, record_type)
        print(f"\n{description} ({record_type} Records):")
        print("-" * 40)
        if records:
            for record in records:
                print(f"  {record}")
        else:
            print("  No records found")

    # Try to get IPv4 addresses for reverse DNS lookup
    a_records = get_dns_records(domain, 'A')
    if a_records and not str(a_records[0]).startswith('Error'):
        print("\nReverse DNS Lookups:")
        print("-" * 40)
        for ip in a_records:
            hostnames = get_reverse_dns(ip)
            print(f"  {ip}:")
            for hostname in hostnames:
                print(f"    → {hostname}")

    print("\n" + "="*60)
    print("END OF REPORT")
    print("="*60)

def main():
    # Get domain from user or use default
    domain = input("Enter domain to analyze (default: google.com): ").strip() or "google.com"
    generate_dns_report(domain)

if __name__ == "__main__":
    main() 