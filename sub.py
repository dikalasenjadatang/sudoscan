import requests
import sys
import json
import socket
from datetime import datetime, timezone
import certifi
import urllib3
import ssl
from queue import Queue
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
from OpenSSL import crypto
import os
import subprocess
import dns.resolver
import whois
import ipinfo

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)  # Inisialisasi colorama untuk warna terminal

# API Token for IPInfo (Replace with your own for better rate limits)
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

def get_subdomains(domain):
    print(f"{Fore.CYAN}[+] Mencari subdomain untuk: {domain}{Style.RESET_ALL}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=10, verify=certifi.where())
        response.raise_for_status()
        data = response.json()

        unwanted_keywords = {"cpanel", "webmail", "cpcalendars", "cpcontacts", "www", "mail", "webdisk", "whm", "*."}
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if any(unwanted in sub for unwanted in unwanted_keywords):
                        continue
                    if sub.endswith(domain):
                        subdomains.add(sub)
        
        return sorted(subdomains)
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error saat request ke crt.sh: {e}{Style.RESET_ALL}")
        return []

def check_subdomain_status(subdomain):
    """Cek status HTTP, HTTPS, header server, dan SSL validity."""
    result = {"subdomain": subdomain, "http": "DOWN", "https": "DOWN", "server": "Unknown", "ssl_valid": "Unknown", "ip": "Unknown", "geo": "Unknown", "reverse_ip": "Unknown", "cname": "Unknown"}
    
    try:
        response_http = requests.get(f"http://{subdomain}", timeout=5)
        result["http"] = response_http.status_code
        result["server"] = response_http.headers.get("Server", "Unknown")
    except requests.RequestException:
        pass
    
    try:
        response_https = requests.get(f"https://{subdomain}", timeout=5, verify=certifi.where())
        result["https"] = response_https.status_code
        result["ssl_valid"] = check_ssl_validity(subdomain)
    except requests.RequestException:
        pass

    # DNS Resolution
    ip = resolve_dns(subdomain)
    result["ip"] = ip
    if ip:
        result["geo"] = get_geo_location(ip)
        result["reverse_ip"] = reverse_ip_lookup(ip)
    
    # CNAME Lookup
    result["cname"] = get_cname(subdomain)
    
    return result

def check_ssl_validity(subdomain):
    """Cek apakah sertifikat SSL valid dan kapan expired."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((subdomain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                cert = ssock.getpeercert(True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                not_after = x509.get_notAfter().decode("utf-8")
                expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                days_remaining = (expiry_date - datetime.now(timezone.utc)).days
                return f"Valid ({days_remaining} days left)" if days_remaining > 0 else "Expired"
    except Exception:
        return "Failed"

def resolve_dns(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None

def get_geo_location(ip):
    try:
        details = ipinfo_handler.getDetails(ip)
        return f"{details.city}, {details.country}"
    except:
        return "Unknown"

def reverse_ip_lookup(ip):
    try:
        hostnames = socket.gethostbyaddr(ip)
        return ", ".join(hostnames[1])
    except socket.herror:
        return "None"

def get_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return answers[0].to_text()
    except:
        return "None"

def screenshot_website(subdomain):
    filename = f"screenshots/{subdomain.replace('.', '_')}.png"
    os.makedirs("screenshots", exist_ok=True)
    try:
        subprocess.run(["cutycapt", f"--url=https://{subdomain}", f"--out={filename}"], timeout=10)
        return filename
    except Exception as e:
        return "Failed"

def sanitize_filename(domain, extension="txt"):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{domain.replace('.', '-')}_{timestamp}.{extension}"

def save_results(filename, results, output_format="txt"):
    if output_format == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
    else:
        with open(filename, "w") as f:
            for result in results:
                f.write(f"{result['subdomain']} - HTTP: {result['http']}, HTTPS: {result['https']}, Server: {result['server']}, SSL: {result['ssl_valid']}, IP: {result['ip']}, Geo: {result['geo']}, Reverse IP: {result['reverse_ip']}, CNAME: {result['cname']}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} domain.com [json]")
        sys.exit(1)

    domain = sys.argv[1]
    output_format = "json" if len(sys.argv) > 2 and sys.argv[2].lower() == "json" else "txt"
    subdomains = get_subdomains(domain)
    filename = sanitize_filename(domain, output_format)
    
    if subdomains:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_subdomain_status, subdomains))
        save_results(filename, results, output_format)
        print(f"{Fore.MAGENTA}[+] Hasil disimpan ke: {filename}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Tidak ada subdomain ditemukan.{Style.RESET_ALL}")
