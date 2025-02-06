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
    message = []
    message.append(f"[~] Resolving {record_type} records for: {domain}")
    try:
        answers = dns.resolver.resolve(domain, record_type)
        message.append(f"[+] Resolution for {record_type} successful")
        return [str(rdata) for rdata in answers], message
    except Exception as e:
        err_msg = f"[ERROR] Failed to resolve {record_type} for {domain}: {str(e)}"
        message.append(err_msg)
        return [f"Error: {str(e)}"], message


def get_reverse_dns(ip_address):
    message = []
    message.append(f"[~] Performing reverse DNS lookup for: {ip_address}")
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        message.append("[+] Reverse resolution successful")
        return [str(rdata) for rdata in answers], message
    except Exception as e:
        err_msg = f"[ERROR] Reverse DNS lookup failed for {ip_address}: {str(e)}"
        message.append(err_msg)
        return [f"Error: {str(e)}"], message


def generate_dns_report(domain):
    report_lines = []
    report_lines.append("\n" + "=" * 60)
    report_lines.append(f"[+] DNS REPORT FOR: {domain}")
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_lines.append(f"[DEBUG] Report generated at: {current_time}")
    report_lines.append("=" * 60 + "\n")

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
        'SRV': 'Service Records'
    }

    # Process each record type
    for record_type, description in record_types.items():
        records, msgs = get_dns_records(domain, record_type)
        report_lines.append(f"\n[~] {description} ({record_type} Records):")
        report_lines.append("-" * 40)
        # Append any messages captured during record retrieval if needed
        for m in msgs:
            report_lines.append(f"{m}")
        if records and not (len(records) == 1 and records[0].startswith('Error')):
            for record in records:
                report_lines.append(f"  {record}")
        else:
            report_lines.append("  No records found or error occurred")

    # Reverse DNS lookups for A records
    a_records, msgs = get_dns_records(domain, 'A')
    if a_records and not (len(a_records) == 1 and a_records[0].startswith('Error')):
        report_lines.append("\n[~] Reverse DNS Lookups for A records:")
        report_lines.append("-" * 40)
        for ip in a_records:
            hostnames, rev_msgs = get_reverse_dns(ip)
            report_lines.append(f"  {ip}:")
            for hostname in hostnames:
                report_lines.append(f"    → {hostname}")
            for m in rev_msgs:
                report_lines.append(f"    {m}")

    report_lines.append("\n" + "=" * 60)
    report_lines.append("[+] END OF REPORT")
    report_lines.append("=" * 60 + "\n")

    # Also print the report to stdout for real-time feedback
    for line in report_lines:
        print(line)

    return "\n".join(report_lines)


def main():
    print("[~] Checking command line arguments...")
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(f"[DEBUG] Domain provided via arguments: {domain}")
    else:
        domain = "google.com"
        print("[DEBUG] No domain provided, defaulting to google.com")

    report = generate_dns_report(domain)

    # Write report to output file
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{domain}_dns_report.txt")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[+] Report written to: {output_file}")
    except Exception as e:
        print(f"[ERROR] Failed to write report to file: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
        sys.exit(1)

print("[+] END: DNS Analysis Tool")
