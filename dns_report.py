#!/usr/bin/env python3
import sys
import re
import socket
import urllib.parse
import subprocess

def is_ip(address):
    """
    Check if the input string is a valid IPv4 or IPv6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

def get_domain_from_url(url):
    """
    Extract the network location (domain) from a URL.
    If URL parsing fails, return the original input.
    """
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc if parsed.netloc else url

def run_nslookup(query, record_type=None):
    """
    Run nslookup for a given query and DNS record type.
    If record_type is provided, it is appended to the nslookup command.
    """
    command = ["nslookup"]
    if record_type:
        # Use the -query flag to specify the DNS record type.
        command.append("-query=" + record_type)
    command.append(query)
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running nslookup: {e.stderr}"

def full_dns_report(input_str):
    """
    Determines whether the input is an IP, URL, or domain name.
    For an IP address, performs a reverse DNS lookup and a forward lookup.
    For a domain name, retrieves common DNS records using nslookup.
    """
    # If input starts with http:// or https://, extract the domain.
    if re.match(r'https?://', input_str):
        domain = get_domain_from_url(input_str)
    else:
        domain = input_str

    # Check if the cleaned input is an IP address.
    if is_ip(domain):
        print(f"Input '{domain}' recognized as an IP address.\n")
        print("=== Reverse DNS Lookup using nslookup ===")
        output = run_nslookup(domain)
        print(output)

        print("=== Hostname Lookup using socket.gethostbyaddr ===")
        try:
            host_info = socket.gethostbyaddr(domain)
            print("Hostname:", host_info[0])
            print("Aliases:", host_info[1] if host_info[1] else "None")
            print("IP addresses:", host_info[2])
        except Exception as e:
            print("Error during socket.gethostbyaddr lookup:", e)
    else:
        print(f"Input '{domain}' recognized as a domain name.\n")
        # List of common DNS record types to query.
        record_types = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]
        for rtype in record_types:
            print(f"=== {rtype} Records ===")
            output = run_nslookup(domain, record_type=rtype)
            print(output)
            print("-" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <IP address, domain name, or URL>".format(sys.argv[0]))
        sys.exit(1)
    input_str = sys.argv[1]
    full_dns_report(input_str)
