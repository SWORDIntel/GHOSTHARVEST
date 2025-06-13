#!/usr/bin/env python3
"""
ORBITAL_EYES Enhanced Domain Intelligence Tool
------------------------------------------------
Features:
- Asynchronous DNS resolution (with CNAME chain capture)
- Asynchronous HTTP header fetching with optional caching
- ASN lookup for each resolved IP (with global caching)
- Enhanced CDN detection from multiple signals
- Generation of an enhanced DOT file (Graphviz network map)
- Improved JSON serialization using an EnhancedJSONEncoder
- Terminal-based GUI interface for improved usability
- Auto-generate configuration on first run and caching of HTTP responses
"""
import asyncio
import socket
import json
import ipaddress
import os
import re
import sys
from datetime import datetime
import ssl
import whois
import dns.resolver
import requests
import nmap
import concurrent.futures
from functools import lru_cache
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
import logging
from rich.logging import RichHandler

def check_dependencies():
    """
    Check for required Python packages and prompt to install if any are missing.
    Add any additional package names to the required_packages list.
    """
    required_packages = ['rich']  # List additional packages here as needed.
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        prompt = (
            "Missing dependencies detected: {}.\n"
            "Would you like to install them now? [Y/n]: ".format(", ".join(missing_packages))
        )
        response = input(prompt).strip().lower()
        if response in ("", "y", "yes"):
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                print("Dependencies installed successfully. Continuing...\n")
            except subprocess.CalledProcessError:
                print("Failed to install dependencies. Please install them manually.")
                sys.exit(1)
        else:
            print("Exiting. Please install the required dependencies and try again.")
            sys.exit(1)

# Call dependency check before proceeding
check_dependencies()

# Async libraries for HTTP, DNS, etc.
import aiohttp
try:
    import aiodns
except ImportError:
    aiodns = None
try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None
# Optional caching for aiohttp
try:
    import aiohttp_client_cache
except ImportError:
    aiohttp_client_cache = None

# For rich terminal UI
console = Console()

# Global ASN lookup cache
asn_cache = {}

# Global configuration
CONFIG = {
    "timeout": 5,
    "max_concurrent_requests": 10,
    "cache_expire_seconds": 600,
    "output_prefix": "orbital_eyes_output",
    "results_dir": "results",
    "temp_dir": "temp",
    "log_level": "INFO",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "subdomain_wordlist": "subdomains.txt",
    "port_scan_range": "80,443,8080,8443,22,21,25,53,3306,5432,27017",
    "user_agent": "ORBITAL_EYES/1.0.0"
}

# Setup logging
logging.basicConfig(
    level=CONFIG["log_level"],
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("ORBITAL_EYES")

# --- Configuration Handling ---
CONFIG_FILE = "orbital_eyes_config.json"

def load_config():
    """Load configuration from file; auto-generate defaults on first run."""
    default_config = {
        "timeout": 5,
        "max_concurrent_requests": 5,
        "cache_expire_seconds": 600,
        "depth": 0,
        "output_prefix": "orbital_eyes_output",
        "domains": []  # Optional: list of domains to scan; can be provided interactively or via CLI.
    }
    
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        console.print(f"[green]No config found – a default config has been generated at {CONFIG_FILE}.[/green]")
        return default_config
    else:
        with open(CONFIG_FILE, "r") as f:
            try:
                config = json.load(f)
            except Exception as e:
                console.print(f"[red]Error reading config file: {e}[/red]")
                config = default_config
        return config

def update_config(new_config):
    """Update and save the configuration file"""
    with open(CONFIG_FILE, "w") as f:
        json.dump(new_config, f, indent=2)
    return new_config

# --- Enhanced JSON Encoder ---
class EnhancedJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime, set, and IP addresses."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(obj)
        return super().default(obj)

# --- DomainInfo Class ---
class DomainInfo:
    def __init__(self, domain, timeout):
        self.domain = domain
        self.timeout = timeout
        self.ip_addresses = []        # List of ipaddress objects
        self.cname_chain = []         # List of any CNAME redirects
        self.headers = {}             # HTTP headers (keys are lowercase)
        self.asn_info = {}            # Dict: ip string -> (ASN, Org)
        self.cdn = None               # Detected CDN provider, if any
        self.ssl_info = {}            # SSL/TLS certificate information
        self.whois_info = {}          # WHOIS information
        self.subdomains = set()       # Discovered subdomains
        self.open_ports = {}          # Open ports and services
        self.technologies = []        # Detected technologies
        self.mx_records = []          # MX records
        self.txt_records = []         # TXT records
        # Additional fields (placeholders; you can later add registrar, SSL, analytics, etc.)
        self.registrar = None
        self.analytics_ids = []
        self.ssl_alt_names = []

    async def resolve_dns(self):
        """Resolve DNS records asynchronously with aiodns (or fallback to synchronous resolution in executor)."""
        if aiodns:
            resolver = aiodns.DNSResolver(timeout=self.timeout)
            name = self.domain
            visited = set()
            while True:
                if name in visited:
                    break
                visited.add(name)
                try:
                    # Query for CNAME record.
                    result = await resolver.query(name, 'CNAME')
                    if result:
                        cname_target = result[0].cname.rstrip('.')
                        self.cname_chain.append(cname_target)
                        name = cname_target
                        continue
                except aiodns.error.DNSError:
                    # No CNAME record.
                    pass
                except Exception as e:
                    console.log(f"[red]DNS CNAME error for {name}: {e}[/red]")
                    break
                break
            # Query A records.
            try:
                a_answers = await resolver.query(name, 'A')
                for r in a_answers:
                    try:
                        self.ip_addresses.append(ipaddress.ip_address(r.host))
                    except Exception:
                        pass
            except Exception as e:
                console.log(f"[red]A record error for {name}: {e}[/red]")
            # Query AAAA records.
            try:
                aaaa_answers = await resolver.query(name, 'AAAA')
                for r in aaaa_answers:
                    try:
                        self.ip_addresses.append(ipaddress.ip_address(r.host))
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            # Fallback: use synchronous resolution
            loop = asyncio.get_event_loop()
            def sync_dns():
                try:
                    res = socket.gethostbyname_ex(self.domain)
                    self.cname_chain.extend(res[1])
                    for ip_str in res[2]:
                        self.ip_addresses.append(ipaddress.ip_address(ip_str))
                except Exception as e:
                    console.log(f"[red]Synchronous DNS failed for {self.domain}: {e}[/red]")
            await loop.run_in_executor(None, sync_dns)
        # Deduplicate IP addresses.
        self.ip_addresses = list(dict.fromkeys(self.ip_addresses))
        return self.ip_addresses

    async def fetch_http_headers(self):
        """Fetch HTTP headers using aiohttp (with optional caching if aiohttp_client_cache available)."""
        url = f"http://{self.domain}"
        session = None
        if aiohttp_client_cache:
            # Use aiohttp_client_cache to enable caching.
            session = aiohttp_client_cache.CachedSession(
                cache_name='orbital_cache', 
                expire_after=CONFIG["cache_expire_seconds"], 
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        else:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        try:
            async with session.head(url, allow_redirects=True) as response:
                self.headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            try:
                async with session.get(url, allow_redirects=True) as response:
                    self.headers = {k.lower(): v for k, v in response.headers.items()}
            except Exception as e:
                console.log(f"[red]HTTP fetch failed for {self.domain}: {e}[/red]")
                self.headers = {}
        finally:
            await session.close()
        return self.headers

    async def lookup_asn(self):
        """Lookup ASN info for each resolved IP. Uses a global cache to avoid duplicate lookups."""
        loop = asyncio.get_event_loop()
        for ip in self.ip_addresses:
            ip_str = str(ip)
            if ip_str in asn_cache:
                self.asn_info[ip_str] = asn_cache[ip_str]
                continue
            def do_lookup(ip_str=ip_str):
                asn = ""
                org = ""
                try:
                    if IPWhois:
                        obj = IPWhois(ip_str)
                        res = obj.lookup_rdap(asn_methods=["whois", "dns"])
                        asn_num = res.get('asn')
                        asn_desc = res.get('asn_description', '')
                        if asn_num:
                            asn = f"AS{asn_num}"
                        if asn_desc:
                            if " - " in asn_desc:
                                org = asn_desc.split(" - ", 1)[1]
                            else:
                                org = asn_desc
                except Exception as e:
                    console.log(f"[yellow]ASN lookup error for {ip_str}: {e}[/yellow]")
                return (asn, org)
            result = await loop.run_in_executor(None, do_lookup)
            asn_cache[ip_str] = result
            self.asn_info[ip_str] = result
        return self.asn_info

    async def detect_cdn(self):
        """Enhanced CDN detection using CNAME chain, HTTP headers, and ASN info."""
        cdn_markers = {
            "Cloudflare": ["cloudflare", "cf-cache-status", "cf-ray"],
            "Akamai": ["akamai", "akamaighost", "x-akamai-"],
            "Fastly": ["fastly", "x-cache", "x-served-by"],
            "CloudFront": ["cloudfront", "x-amz-cf-"],
            "Incapsula": ["incapsula", "imperva"],
            "EdgeCast": ["edgecast"],
            "Limelight": ["limelight"],
            "Azure": ["azureedge.net", "azurecdn"],
            "Google": ["googleservices", "x-google-cache"]
        }
        
        detected = None
        
        # Check CNAME chain:
        for cname in self.cname_chain:
            cname_lower = cname.lower()
            for provider, markers in cdn_markers.items():
                if any(marker in cname_lower for marker in markers):
                    detected = provider
                    break
            if detected:
                break
                
        # Check HTTP headers if needed:
        if not detected:
            for provider, markers in cdn_markers.items():
                for h_name, h_val in self.headers.items():
                    if any(marker in f"{h_name}: {h_val}".lower() for marker in markers):
                        detected = provider
                        break
                if detected:
                    break
                    
        # Check ASN info:
        if not detected:
            for ip, (asn, org) in self.asn_info.items():
                combined = f"{asn} {org}".lower()
                if "cloudflare" in combined:
                    detected = "Cloudflare"
                elif "akamai" in combined:
                    detected = "Akamai"
                elif "fastly" in combined:
                    detected = "Fastly"
                if detected:
                    break
                    
        self.cdn = detected
        return self.cdn

    async def get_ssl_info(self):
        """Get SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.ssl_info = {
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "subject": dict(x[0] for x in cert["subject"]),
                        "version": cert["version"],
                        "notBefore": cert["notBefore"],
                        "notAfter": cert["notAfter"],
                        "serialNumber": cert["serialNumber"]
                    }
        except Exception as e:
            logger.error(f"SSL info fetch error for {self.domain}: {e}")

    async def get_whois_info(self):
        """Get WHOIS information"""
        try:
            w = whois.whois(self.domain)
            self.whois_info = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "emails": w.emails,
                "org": w.org,
                "country": w.country
            }
        except Exception as e:
            logger.error(f"WHOIS lookup error for {self.domain}: {e}")

    async def enumerate_subdomains(self):
        """Enumerate subdomains using wordlist"""
        try:
            if not os.path.exists(CONFIG["subdomain_wordlist"]):
                logger.warning(f"Subdomain wordlist not found: {CONFIG['subdomain_wordlist']}")
                return

            with open(CONFIG["subdomain_wordlist"], "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]

            async def check_subdomain(subdomain: str) -> None:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = CONFIG["dns_servers"]
                    full_domain = f"{subdomain}.{self.domain}"
                    answers = resolver.resolve(full_domain, 'A')
                    self.subdomains.add(full_domain)
                except:
                    pass

            tasks = [check_subdomain(sub) for sub in subdomains]
            await asyncio.gather(*tasks)

        except Exception as e:
            logger.error(f"Subdomain enumeration error for {self.domain}: {e}")

    async def port_scan(self):
        """Perform port scanning"""
        try:
            nm = nmap.PortScanner()
            ports = CONFIG["port_scan_range"]
            nm.scan(self.domain, ports, arguments='-sV')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            service = nm[host][proto][port].get('name', 'unknown')
                            self.open_ports[port] = service

        except Exception as e:
            logger.error(f"Port scan error for {self.domain}: {e}")

    async def detect_technologies(self):
        """Detect technologies used by the website"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{self.domain}",
                                     headers={"User-Agent": CONFIG["user_agent"]},
                                     timeout=CONFIG["timeout"]) as response:
                    html = await response.text()
                    headers = response.headers

            # Check for common technologies
            tech_indicators = {
                "WordPress": ["wp-content", "wp-includes"],
                "Drupal": ["drupal", "sites/all"],
                "Joomla": ["joomla", "administrator"],
                "Apache": ["Apache", "Server: Apache"],
                "Nginx": ["nginx", "Server: nginx"],
                "PHP": ["PHP", "X-Powered-By: PHP"],
                "Node.js": ["X-Powered-By: Express"],
                "React": ["react", "react-dom"],
                "Vue.js": ["vue", "vue.js"],
                "jQuery": ["jquery", "jQuery"],
                "Bootstrap": ["bootstrap", "bootstrap.min.css"]
            }

            for tech, indicators in tech_indicators.items():
                if any(indicator.lower() in html.lower() for indicator in indicators):
                    self.technologies.append({"name": tech, "confidence": "high"})
                elif any(indicator.lower() in str(headers).lower() for indicator in indicators):
                    self.technologies.append({"name": tech, "confidence": "medium"})

        except Exception as e:
            logger.error(f"Technology detection error for {self.domain}: {e}")

# --- Network Graph Generation ---
def generate_network_graph(domain_infos, output_prefix):
    """
    Generate an enhanced DOT file representing relationships among domains.
    Attributes include: shared IP addresses and (if available) registrar or analytics nodes.
    """
    dot_file = f"{output_prefix}.dot"
    with open(dot_file, "w") as f:
        f.write("graph DomainNetwork {\n")
        f.write("  overlap=false; splines=true;\n")
        # Define a node for each domain (ellipse, light blue)
        for di in domain_infos:
            f.write(f'  "{di.domain}" [shape=ellipse style=filled fillcolor=lightblue];\n')
        # Define attribute nodes (here we illustrate by IP addresses)
        ip_nodes = set()
        for di in domain_infos:
            for ip in di.ip_addresses:
                ip_label = f"IP: {ip}"
                ip_nodes.add(ip_label)
        for ip_label in ip_nodes:
            f.write(f'  "{ip_label}" [shape=box style=filled fillcolor=lightgrey];\n')
        # Create edges from domain to IP if the domain resolves to that IP
        for di in domain_infos:
            for ip in di.ip_addresses:
                f.write(f'  "{di.domain}" -- "IP: {ip}";\n')
        # [Optional] Connect domains that share the same CDN.
        cdn_nodes = {}
        for di in domain_infos:
            if di.cdn:
                cdn_nodes.setdefault(di.cdn, set()).add(di.domain)
        for cdn, domains in cdn_nodes.items():
            label = f"CDN: {cdn}"
            f.write(f'  "{label}" [shape=box style=filled fillcolor=yellow];\n')
            for d in domains:
                f.write(f'  "{d}" -- "{label}";\n')
        f.write("}\n")
    console.print(f"[green]DOT file generated: {dot_file}[/green]")
    # Attempt PNG rendering if Graphviz dot command is available.
    try:
        import shutil, subprocess
        if shutil.which("dot"):
            png_file = f"{output_prefix}.png"
            subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file], check=True)
            console.print(f"[green]Network graph image generated: {png_file}[/green]")
        else:
            console.print("[yellow]Graphviz 'dot' not found – only DOT file generated.[/yellow]")
    except Exception as e:
        console.print(f"[red]Graphviz rendering failed: {e}[/red]")

# --- Main Asynchronous Processing ---
async def process_domain(domain, timeout, progress):
    """
    Process a single domain asynchronously and update progress using the shared Progress instance.
    
    Parameters:
    domain (str): Domain name.
    timeout (int): Request timeout.
    progress (Progress): Shared progress object for updating status.
    
    Returns:
    DomainInfo: An object containing analysis results for the domain.
    """
    di = DomainInfo(domain, timeout)
    
    # DNS Resolution
    task_dns = progress.add_task(f"Resolving DNS for {domain}...", total=1)
    await di.resolve_dns()
    progress.update(task_dns, completed=1)
    
    # HTTP Headers
    task_http = progress.add_task(f"Fetching HTTP headers for {domain}...", total=1)
    await di.fetch_http_headers()
    progress.update(task_http, completed=1)
    
    # ASN Lookup
    task_asn = progress.add_task(f"Performing ASN lookup for {domain}...", total=1)
    await di.lookup_asn()
    progress.update(task_asn, completed=1)
    
    # CDN Detection
    task_cdn = progress.add_task(f"Detecting CDN for {domain}...", total=1)
    await di.detect_cdn()
    progress.update(task_cdn, completed=1)
    
    # SSL/TLS Analysis
    task_ssl = progress.add_task(f"Analyzing SSL/TLS for {domain}...", total=1)
    await di.get_ssl_info()
    progress.update(task_ssl, completed=1)
    
    # WHOIS Lookup
    task_whois = progress.add_task(f"Performing WHOIS lookup for {domain}...", total=1)
    await di.get_whois_info()
    progress.update(task_whois, completed=1)
    
    # Subdomain Enumeration
    task_subdomains = progress.add_task(f"Enumerating subdomains for {domain}...", total=1)
    await di.enumerate_subdomains()
    progress.update(task_subdomains, completed=1)
    
    # Port Scanning
    task_ports = progress.add_task(f"Scanning ports for {domain}...", total=1)
    await di.port_scan()
    progress.update(task_ports, completed=1)
    
    # Technology Detection
    task_tech = progress.add_task(f"Detecting technologies for {domain}...", total=1)
    await di.detect_technologies()
    progress.update(task_tech, completed=1)
    
    # Display results
    console.print(f"[bold blue]{domain}[/bold blue]")
    console.print(f" IPs: {', '.join(str(ip) for ip in di.ip_addresses) or 'None'}")
    asn_str = ', '.join(f"{ip}: {asn} {org}".strip() for ip, (asn, org) in di.asn_info.items() if asn)
    console.print(f" ASN Info: {asn_str or 'None'}")
    console.print(f" CDN: {('[green]'+di.cdn+'[/green]') if di.cdn else 'None detected'}")
    
    if di.ssl_info:
        console.print("\n[bold]SSL/TLS Information:[/bold]")
        console.print(f" Issuer: {di.ssl_info.get('issuer', {}).get('organizationName', 'Unknown')}")
        console.print(f" Valid From: {di.ssl_info.get('notBefore', 'Unknown')}")
        console.print(f" Valid Until: {di.ssl_info.get('notAfter', 'Unknown')}")
    
    if di.whois_info:
        console.print("\n[bold]WHOIS Information:[/bold]")
        console.print(f" Registrar: {di.whois_info.get('registrar', 'Unknown')}")
        console.print(f" Creation Date: {di.whois_info.get('creation_date', 'Unknown')}")
        console.print(f" Expiration Date: {di.whois_info.get('expiration_date', 'Unknown')}")
    
    if di.subdomains:
        console.print("\n[bold]Discovered Subdomains:[/bold]")
        for subdomain in sorted(di.subdomains):
            console.print(f" • {subdomain}")
    
    if di.open_ports:
        console.print("\n[bold]Open Ports:[/bold]")
        for port, service in sorted(di.open_ports.items()):
            console.print(f" • {port}/tcp - {service}")
    
    if di.technologies:
        console.print("\n[bold]Detected Technologies:[/bold]")
        for tech in di.technologies:
            console.print(f" • {tech['name']} ({tech['confidence']} confidence)")
    
    return di

async def main_async(domains, timeout, max_concurrent):
    """
    Process a list of domains concurrently with a semaphore for limiting concurrency.
    Uses a single, shared Progress instance to update status.
    
    Parameters:
    domains (list): List of domains.
    timeout (int): Request timeout.
    max_concurrent (int): Maximum concurrent tasks.
    
    Returns:
    list: List of DomainInfo objects.
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def sem_task(domain, progress):
        async with semaphore:
            return await process_domain(domain, timeout, progress)
    
    # Create a shared Progress instance.
    progress = Progress(
        SpinnerColumn(), 
        TextColumn("{task.description}"), 
        transient=True, 
        console=console
    )
    
    with progress:
        tasks = [sem_task(domain, progress) for domain in domains]
        results = await asyncio.gather(*tasks)
    return results

# --- Main GUI and Control Functions ---
def run_domain_analysis():
    """Run the domain analysis with user-specified domains"""
    console.clear()
    console.print(Panel("[bold cyan]Domain Analysis[/bold cyan]", border_style="cyan"))
    
    # Domain input options
    console.print("[bold]Domain Input Options:[/bold]")
    options_table = Table(show_header=False, box=None, padding=(0, 2))
    options_table.add_column(style="cyan")
    options_table.add_column()
    
    options_table.add_row("1", "Enter domains manually")
    options_table.add_row("2", "Use domains from config file")
    options_table.add_row("3", "Read domains from a file")
    options_table.add_row("0", "Return to main menu")
    
    console.print(Panel(options_table, border_style="blue"))
    
    option = Prompt.ask("Select an option", choices=["0", "1", "2", "3"], default="1")
    
    if option == "0":
        return
    
    domains = []
    
    if option == "1":
        # Manual input
        while True:
            domain = Prompt.ask("Enter a domain name (or leave blank to finish)")
            if not domain:
                break
            domains.append(domain)
            console.print(f"Added: [cyan]{domain}[/cyan]")
        
        if not domains:
            console.print("[yellow]No domains entered. Returning to main menu.[/yellow]")
            return
            
    elif option == "2":
        # Use from config
        domains = CONFIG.get("domains", [])
        if not domains:
            console.print("[yellow]No domains found in config file.[/yellow]")
            if Confirm.ask("Do you want to enter domains manually?"):
                return run_domain_analysis()
            return
            
        domains_str = ", ".join(f"[cyan]{d}[/cyan]" for d in domains)
        console.print(f"Using domains from config: {domains_str}")
        if not Confirm.ask("Continue with these domains?", default=True):
            return
            
    elif option == "3":
        # Read from file
        filepath = Prompt.ask("Enter the path to your domains file")
        try:
            with open(filepath, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if not domains:
                console.print("[yellow]No domains found in the file.[/yellow]")
                return
                
            domains_str = ", ".join(f"[cyan]{d}[/cyan]" for d in domains[:5])
            if len(domains) > 5:
                domains_str += f" and {len(domains)-5} more"
                
            console.print(f"Loaded {len(domains)} domains: {domains_str}")
            if not Confirm.ask("Continue with these domains?", default=True):
                return
                
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            return
    
    # Confirm and run analysis
    console.print("\n[bold]Analysis Options:[/bold]")
    max_concurrent = Prompt.ask(
        "Maximum concurrent requests", 
        default=str(CONFIG["max_concurrent_requests"]),
        choices=[str(i) for i in range(1, 21)]
    )
    timeout = Prompt.ask(
        "Request timeout (seconds)", 
        default=str(CONFIG["timeout"]),
        choices=[str(i) for i in range(1, 31)]
    )
    
    console.print(Panel(
        f"[bold]Ready to analyze {len(domains)} domains[/bold]\n"
        f"Max concurrent requests: {max_concurrent}\n"
        f"Timeout: {timeout} seconds",
        border_style="green"
    ))
    
    if not Confirm.ask("Start analysis now?", default=True):
        return
    
    # Run the analysis
    loop = asyncio.get_event_loop()
    domain_infos = loop.run_until_complete(
        main_async(domains, int(timeout), int(max_concurrent))
    )
    
    # Save results
    output_json = f"{CONFIG['output_prefix']}_results.json"
    out_data = []
    for di in domain_infos:
        out_data.append({
            "domain": di.domain,
            "ip_addresses": [str(ip) for ip in di.ip_addresses],
            "cname_chain": di.cname_chain,
            "headers": di.headers,
            "asn_info": di.asn_info,
            "cdn": di.cdn
        })
    
    with open(output_json, "w") as f:
        json.dump(out_data, f, cls=EnhancedJSONEncoder, indent=2)
    
    console.print(f"[green]Results saved to {output_json}[/green]")
    
    # Generate network graph
    generate_network_graph(domain_infos, CONFIG["output_prefix"])
    
    # Results summary
    console.print("\n[bold cyan]Analysis Summary:[/bold cyan]")
    results_table = Table(show_header=True, header_style="bold blue")
    results_table.add_column("Domain")
    results_table.add_column("IPs")
    results_table.add_column("CDN")
    
    for di in domain_infos:
        results_table.add_row(
            di.domain,
            ", ".join(str(ip) for ip in di.ip_addresses)[:30] + ("..." if len(", ".join(str(ip) for ip in di.ip_addresses)) > 30 else ""),
            di.cdn or "None"
        )
    
    console.print(results_table)

def configure_settings():
    """Configure tool settings"""
    console.clear()
    console.print(Panel("[bold cyan]Configuration Settings[/bold cyan]", border_style="cyan"))
    
    # Show current config
    config_table = Table(show_header=True)
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value")
    
    for key, value in CONFIG.items():
        if key == "domains":
            domains_str = ", ".join(value) if value else "None configured"
            if len(domains_str) > 50:
                domains_str = domains_str[:47] + "..."
            config_table.add_row(key, domains_str)
        else:
            config_table.add_row(key, str(value))
    
    console.print(config_table)
    console.print("\n[bold]Select a setting to modify:[/bold]")
    
    options_table = Table(show_header=False, box=None, padding=(0, 2))
    options_table.add_column(style="cyan")
    options_table.add_column()
    
    options_table.add_row("1", "Change timeout")
    options_table.add_row("2", "Change max concurrent requests")
    options_table.add_row("3", "Change cache expiry time")
    options_table.add_row("4", "Change output prefix")
    options_table.add_row("5", "Manage default domains list")
    options_table.add_row("0", "Return to main menu")
    
    console.print(Panel(options_table, border_style="blue"))
    
    option = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5"], default="0")
    
    if option == "0":
        return
        
    if option == "1":
        timeout = Prompt.ask(
            "Enter new timeout (seconds)", 
            default=str(CONFIG["timeout"])
        )
        CONFIG["timeout"] = int(timeout)
        
    elif option == "2":
        max_concurrent = Prompt.ask(
            "Enter new max concurrent requests", 
            default=str(CONFIG["max_concurrent_requests"])
        )
        CONFIG["max_concurrent_requests"] = int(max_concurrent)
        
    elif option == "3":
        cache_expire = Prompt.ask(
            "Enter new cache expiry time (seconds)", 
            default=str(CONFIG["cache_expire_seconds"])
        )
        CONFIG["cache_expire_seconds"] = int(cache_expire)
        
    elif option == "4":
        prefix = Prompt.ask(
            "Enter new output file prefix", 
            default=CONFIG["output_prefix"]
        )
        CONFIG["output_prefix"] = prefix
        
    elif option == "5":
        manage_domains_list()
        return  # Return to manage_domains_list handles return to main menu
    
    # Save the updated config
    update_config(CONFIG)
    console.print("[green]Configuration updated successfully![/green]")

def manage_domains_list():
    """Manage the default domains list in the config"""
    while True:
        console.clear()
        console.print(Panel("[bold cyan]Manage Default Domains List[/bold cyan]", border_style="cyan"))
        
        domains = CONFIG.get("domains", [])
        if domains:
            console.print("[bold]Current domains:[/bold]")
            for i, domain in enumerate(domains, 1):
                console.print(f"{i}. [cyan]{domain}[/cyan]")
        else:
            console.print("[yellow]No domains configured.[/yellow]")
        
        console.print("\n[bold]Options:[/bold]")
        options_table = Table(show_header=False, box=None, padding=(0, 2))
        options_table.add_column(style="cyan")
        options_table.add_column()
        
        options_table.add_row("1", "Add a domain")
        options_table.add_row("2", "Remove a domain")
        options_table.add_row("3", "Clear all domains")
        options_table.add_row("4", "Import domains from a file")
        options_table.add_row("0", "Return to settings")
        
        console.print(Panel(options_table, border_style="blue"))
        
        option = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4"], default="0")
        
        if option == "0":
            return
            
        if option == "1":
            domain = Prompt.ask("Enter the domain to add")
            if domain:
                if domain not in domains:
                    domains.append(domain)
                    CONFIG["domains"] = domains
                    update_config(CONFIG)
                    console.print(f"[green]Added domain: {domain}[/green]")
                else:
                    console.print(f"[yellow]Domain {domain} already exists in the list.[/yellow]")
                    
        elif option == "2":
            if not domains:
                console.print("[yellow]No domains to remove.[/yellow]")
                continue
                
            idx = Prompt.ask(
                "Enter the number of the domain to remove", 
                choices=[str(i) for i in range(1, len(domains)+1)],
                default="1"
            )
            removed = domains.pop(int(idx)-1)
            CONFIG["domains"] = domains
            update_config(CONFIG)
            console.print(f"[green]Removed domain: {removed}[/green]")
            
        elif option == "3":
            if Confirm.ask("Are you sure you want to remove ALL domains?", default=False):
                CONFIG["domains"] = []
                update_config(CONFIG)
                console.print("[green]All domains have been removed.[/green]")
                
        elif option == "4":
            filepath = Prompt.ask("Enter the path to your domains file")
            try:
                with open(filepath, 'r') as f:
                    new_domains = [line.strip() for line in f if line.strip()]
                
                if not new_domains:
                    console.print("[yellow]No domains found in the file.[/yellow]")
                    continue
                    
                # Ask if replace or append
                action = Prompt.ask(
                    "Do you want to replace or append to current domains?",
                    choices=["replace", "append"],
                    default="append"
                )
                
                if action == "replace":
                    CONFIG["domains"] = new_domains
                else:  # append
                    for d in new_domains:
                        if d not in domains:
                            domains.append(d)
                    CONFIG["domains"] = domains
                
                update_config(CONFIG)
                console.print(f"[green]Successfully imported {len(new_domains)} domains![/green]")
                    
            except Exception as e:
                console.print(f"[red]Error reading file: {e}[/red]")
                
        # Wait for user to acknowledge
        Prompt.ask("Press Enter to continue", default="")

def view_recent_results():
    """View and manage recent analysis results"""
    console.clear()
    console.print(Panel("[bold cyan]Recent Analysis Results[/bold cyan]", border_style="cyan"))
    
    # Find result files
    import glob
    result_files = glob.glob(f"{CONFIG['output_prefix']}*_results.json")
    
    if not result_files:
        console.print("[yellow]No analysis results found.[/yellow]")
        return
    
    # Sort by modification time (most recent first)
    result_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    console.print("[bold]Recent result files:[/bold]")
    for i, file in enumerate(result_files[:10], 1):
        timestamp = datetime.fromtimestamp(os.path.getmtime(file))
        console.print(f"{i}. [cyan]{file}[/cyan] - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    console.print("\n[bold]Options:[/bold]")
    options_table = Table(show_header=False, box=None, padding=(0, 2))
    options_table.add_column(style="cyan")
    options_table.add_column()
    
    options_table.add_row("1", "View a result file")
    options_table.add_row("2", "Export results to CSV")
    options_table.add_row("3", "Compare two result files")
    options_table.add_row("0", "Return to main menu")
    
    console.print(Panel(options_table, border_style="blue"))
    
    option = Prompt.ask("Select an option", choices=["0", "1", "2", "3"], default="0")
    
    if option == "0":
        return
        
    if option == "1":
        idx = Prompt.ask(
            "Enter the number of the file to view", 
            choices=[str(i) for i in range(1, min(len(result_files), 10) + 1)],
            default="1"
        )
        file = result_files[int(idx)-1]
        
        try:
            with open(file, 'r') as f:
                data = json.load(f)
            
            console.clear()
            console.print(Panel(f"[bold cyan]Viewing Results: {file}[/bold cyan]", border_style="cyan"))
            
            for domain_data in data:
                console.print(f"[bold blue]{domain_data['domain']}[/bold blue]")
                console.print(f" IPs: {', '.join(domain_data['ip_addresses']) or 'None'}")
                console.print(f" CNAME Chain: {', '.join(domain_data['cname_chain']) or 'None'}")
                console.print(f" CDN: {domain_data['cdn'] or 'None detected'}")
                console.print("---")
            
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
    
    elif option == "2":
        idx = Prompt.ask(
            "Enter the number of the file to export", 
            choices=[str(i) for i in range(1, min(len(result_files), 10) + 1)],
            default="1"
        )
        file = result_files[int(idx)-1]
        
        try:
            with open(file, 'r') as f:
                data = json.load(f)
            
            # Export to CSV
            import csv
            csv_file = file.replace('.json', '.csv')
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Domain', 'IP Addresses', 'CNAME Chain', 'CDN'])
                
                # Write data
                for domain_data in data:
                    writer.writerow([
                        domain_data['domain'],
                        ', '.join(domain_data['ip_addresses']),
                        ', '.join(domain_data['cname_chain']),
                        domain_data['cdn'] or 'None'
                    ])
            
            console.print(f"[green]Exported to CSV: {csv_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error exporting file: {e}[/red]")
    
    elif option == "3":
        if len(result_files) < 2:
            console.print("[yellow]Need at least two result files to compare.[/yellow]")
            return
            
        idx1 = Prompt.ask(
            "Enter the number of the first file", 
            choices=[str(i) for i in range(1, min(len(result_files), 10) + 1)],
            default="1"
        )
        idx2 = Prompt.ask(
            "Enter the number of the second file", 
            choices=[str(i) for i in range(1, min(len(result_files), 10) + 1)],
            default="2" if idx1 != "2" else "1"
        )
        
        if idx1 == idx2:
            console.print("[yellow]Please select two different files.[/yellow]")
            return
            
        file1 = result_files[int(idx1)-1]
        file2 = result_files[int(idx2)-1]
        
        try:
            with open(file1, 'r') as f:
                data1 = json.load(f)
            with open(file2, 'r') as f:
                data2 = json.load(f)
            
            # Create domain lookup dictionaries
            domains1 = {d['domain']: d for d in data1}
            domains2 = {d['domain']: d for d in data2}
            
            # Find common domains
            common_domains = set(domains1.keys()) & set(domains2.keys())
            only_in_1 = set(domains1.keys()) - set(domains2.keys())
            only_in_2 = set(domains2.keys()) - set(domains1.keys())
            
            console.clear()
            console.print(Panel(f"[bold cyan]Comparing Results[/bold cyan]\n{file1}\n{file2}", border_style="cyan"))
            
            console.print(f"[green]Domains in both files: {len(common_domains)}[/green]")
            console.print(f"[yellow]Domains only in first file: {len(only_in_1)}[/yellow]")
            console.print(f"[yellow]Domains only in second file: {len(only_in_2)}[/yellow]")
            
            if common_domains:
                console.print("\n[bold]Differences in common domains:[/bold]")
                
                for domain in sorted(common_domains):
                    d1 = domains1[domain]
                    d2 = domains2[domain]
                    
                    # Compare IP addresses
                    ips1 = set(d1['ip_addresses'])
                    ips2 = set(d2['ip_addresses'])
                    
                    if ips1 != ips2:
                        console.print(f"[bold blue]{domain}[/bold blue] - IP changes:")
                        console.print(f"  Removed: {', '.join(ips1 - ips2) or 'None'}")
                        console.print(f"  Added: {', '.join(ips2 - ips1) or 'None'}")
                    
                    # Compare CDN
                    if d1['cdn'] != d2['cdn']:
                        console.print(f"[bold blue]{domain}[/bold blue] - CDN changed:")
                        console.print(f"  From: {d1['cdn'] or 'None'}")
                        console.print(f"  To: {d2['cdn'] or 'None'}")
            
        except Exception as e:
            console.print(f"[red]Error comparing files: {e}[/red]")

def show_about():
    """Display information about the tool"""
    console.clear()
    console.print(Panel(
        "[bold cyan]ORBITAL_EYES Enhanced Domain Intelligence Tool[/bold cyan]\n"
        "Version 1.0.0\n\n"
        "[bold]Features:[/bold]\n"
        "• Asynchronous DNS resolution with CNAME chain capture\n"
        "• HTTP header fetching with optional caching\n"
        "• ASN lookup for each resolved IP\n"
        "• Enhanced CDN detection from multiple signals\n"
        "• Network graph generation (Graphviz DOT and PNG)\n"
        "• Results exportable to JSON and CSV\n\n"
        "[bold]Dependencies:[/bold]\n"
        "• Required: aiohttp, rich\n"
        "• Optional: aiodns, ipwhois, aiohttp_client_cache, graphviz\n\n"
        "[dim]Codename: SATELLITE_STALKER\n"
        "Developed for high-level Cybersecurity Operations[/dim]",
        title="About", 
        border_style="cyan"
    ))

def handle_capmonster():
    """Handle CapMonster functionality"""
    console.clear()
    console.print(Panel("[bold cyan]CapMonster Functions[/bold cyan]", border_style="cyan"))
    
    options_table = Table(show_header=False, box=None, padding=(0, 2))
    options_table.add_column(style="cyan")
    options_table.add_column()
    
    options_table.add_row("1", "Get Balance")
    options_table.add_row("2", "Get Task Result")
    options_table.add_row("3", "Create Task")
    options_table.add_row("4", "Get Task Cost")
    options_table.add_row("5", "Get Queue Stats")
    options_table.add_row("6", "Get Software Info")
    options_table.add_row("7", "Get Software Version")
    options_table.add_row("8", "Get Software Updates")
    options_table.add_row("9", "Get Software Settings")
    options_table.add_row("10", "Get Software Status")
    options_table.add_row("11", "Get Software Logs")
    options_table.add_row("12", "Get Software Errors")
    options_table.add_row("13", "Get Software Warnings")
    options_table.add_row("14", "Get Software Debug")
    options_table.add_row("15", "Get Software Info")
    options_table.add_row("16", "Get Software Version")
    options_table.add_row("17", "Get Software Updates")
    options_table.add_row("18", "Get Software Settings")
    options_table.add_row("19", "Get Software Status")
    options_table.add_row("20", "Get Software Logs")
    options_table.add_row("0", "Return to main menu")
    
    console.print(Panel(options_table, border_style="blue"))
    
    option = Prompt.ask("Select a CapMonster function", choices=[str(i) for i in range(21)], default="0")
    
    if option == "0":
        return
        
    # Get API key if not already set
    if not hasattr(handle_capmonster, 'api_key'):
        handle_capmonster.api_key = Prompt.ask("Enter your CapMonster API key")
    
    # Initialize CapMonster client
    if not hasattr(handle_capmonster, 'client'):
        from capmonster import CapMonster
        handle_capmonster.client = CapMonster(handle_capmonster.api_key)
    
    try:
        if option == "1":
            result = handle_capmonster.client.get_balance()
            console.print(f"[green]Balance: {result}[/green]")
            
        elif option == "2":
            task_id = Prompt.ask("Enter task ID")
            result = handle_capmonster.client.get_task_result(task_id)
            console.print(f"[green]Task Result: {result}[/green]")
            
        elif option == "3":
            task_type = Prompt.ask("Enter task type")
            website_url = Prompt.ask("Enter website URL")
            website_key = Prompt.ask("Enter website key")
            result = handle_capmonster.client.create_task(task_type, website_url, website_key)
            console.print(f"[green]Task Created: {result}[/green]")
            
        elif option == "4":
            task_type = Prompt.ask("Enter task type")
            result = handle_capmonster.client.get_task_cost(task_type)
            console.print(f"[green]Task Cost: {result}[/green]")
            
        elif option == "5":
            result = handle_capmonster.client.get_queue_stats()
            console.print(f"[green]Queue Stats: {result}[/green]")
            
        elif option == "6":
            result = handle_capmonster.client.get_software_info()
            console.print(f"[green]Software Info: {result}[/green]")
            
        elif option == "7":
            result = handle_capmonster.client.get_software_version()
            console.print(f"[green]Software Version: {result}[/green]")
            
        elif option == "8":
            result = handle_capmonster.client.get_software_updates()
            console.print(f"[green]Software Updates: {result}[/green]")
            
        elif option == "9":
            result = handle_capmonster.client.get_software_settings()
            console.print(f"[green]Software Settings: {result}[/green]")
            
        elif option == "10":
            result = handle_capmonster.client.get_software_status()
            console.print(f"[green]Software Status: {result}[/green]")
            
        elif option == "11":
            result = handle_capmonster.client.get_software_logs()
            console.print(f"[green]Software Logs: {result}[/green]")
            
        elif option == "12":
            result = handle_capmonster.client.get_software_errors()
            console.print(f"[green]Software Errors: {result}[/green]")
            
        elif option == "13":
            result = handle_capmonster.client.get_software_warnings()
            console.print(f"[green]Software Warnings: {result}[/green]")
            
        elif option == "14":
            result = handle_capmonster.client.get_software_debug()
            console.print(f"[green]Software Debug: {result}[/green]")
            
        elif option == "15":
            result = handle_capmonster.client.get_software_info()
            console.print(f"[green]Software Info: {result}[/green]")
            
        elif option == "16":
            result = handle_capmonster.client.get_software_version()
            console.print(f"[green]Software Version: {result}[/green]")
            
        elif option == "17":
            result = handle_capmonster.client.get_software_updates()
            console.print(f"[green]Software Updates: {result}[/green]")
            
        elif option == "18":
            result = handle_capmonster.client.get_software_settings()
            console.print(f"[green]Software Settings: {result}[/green]")
            
        elif option == "19":
            result = handle_capmonster.client.get_software_status()
            console.print(f"[green]Software Status: {result}[/green]")
            
        elif option == "20":
            result = handle_capmonster.client.get_software_logs()
            console.print(f"[green]Software Logs: {result}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
    
    # Wait for user to acknowledge
    Prompt.ask("Press Enter to continue", default="")

def main():
    """Main entry point with terminal-based GUI menu"""
    global CONFIG
    CONFIG = load_config()
    
    # Main menu loop
    while True:
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]ORBITAL_EYES Enhanced Domain Intelligence Tool[/bold cyan]\n"
            "A comprehensive domain analysis and network mapping utility\n"
            "[dim]Codename: SATELLITE_STALKER[/dim]",
            title="🛰️ ORBITAL_EYES", 
            border_style="cyan"
        ))
        
        menu_table = Table(show_header=False, box=None, padding=(0, 2))
        menu_table.add_column(style="cyan")
        menu_table.add_column()
        
        menu_table.add_row("1", "[bold]Analyze Domains[/bold]")
        menu_table.add_row("2", "[bold]Configure Settings[/bold]")
        menu_table.add_row("3", "[bold]View Recent Results[/bold]")
        menu_table.add_row("4", "[bold]CapMonster Functions[/bold]")
        menu_table.add_row("5", "[bold]About & Help[/bold]")
        menu_table.add_row("0", "[bold red]Exit[/bold red]")
        
        console.print(Panel(menu_table, border_style="blue"))
        
        choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5"], default="1")
        
        if choice == "0":
            console.print("[yellow]Exiting ORBITAL_EYES. Goodbye![/yellow]")
            sys.exit(0)
        
        elif choice == "1":
            run_domain_analysis()
            
        elif choice == "2":
            configure_settings()
            
        elif choice == "3":
            view_recent_results()
            
        elif choice == "4":
            handle_capmonster()
            
        elif choice == "5":
            show_about()
        
        # Prompt to continue
        console.print("\n")
        if not Confirm.ask("Return to main menu?", default=True):
            console.print("[yellow]Exiting ORBITAL_EYES. Goodbye![/yellow]")
            sys.exit(0)

if __name__ == "__main__":
    main()
