#!/usr/bin/env python3
"""
SiteExplorer - Advanced Web Application Reconnaissance and Vulnerability Scanner
--------------------------------------------------------------------------------
A comprehensive site exploration, enumeration, and vulnerability analysis system 
that integrates subdomain discovery, crawling, enumeration, and vulnerability scanning.

This module orchestrates the entire reconnaissance and scanning process:
1. Pre-enumeration (subdomain discovery, infrastructure mapping)
2. Crawling (page discovery, content analysis)
3. Enumeration (technology identification, endpoint discovery)
4. Vulnerability scanning (using integrated scanners)
5. Result correlation and analysis
6. Machine learning integration for enhanced detection
"""

import os
import sys
import json
import time
import logging
import threading
import concurrent.futures
import asyncio
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Any, Optional, Tuple, Union
import re
import ssl

# Add project root to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import existing components
from Libraries.banner_scanner.Enumerator import SiteEnumerator
from Libraries.banner_scanner.ComprehensiveScanner import ComprehensiveScanner
from Libraries.banner_scanner.VulnerabilityCorrelationEngine import VulnerabilityCorrelationEngine
from Libraries.banner_scanner.http_scanner import EnhancedHTTPScanner
from Libraries.banner_scanner.base_scanner import BaseBannerScanner

# Attempt to import Pre_Enumeration tools and new SubdomainEnumeration API
try:
    # Import the new SubdomainEnumeration API (preferred approach)
    from Libraries.SubdomainEnumeration.api import SubdomainEnumerationAPI
    HAS_SUBDOMAIN_API = True
except ImportError:
    HAS_SUBDOMAIN_API = False

try:
    # Keep backward compatibility imports
    from Pre_Enumeration.CAPHARVEST import CAPHarvester
    from Pre_Enumeration.OrbitalEyes import OrbitalEyes
    HAS_PRE_ENUM = True
except ImportError:
    HAS_PRE_ENUM = False

# Attempt to import ML modules
try:
    from Libraries.Chains.Generator.ml_vulnerability_detector import MLVulnerabilityDetector
    HAS_ML = True
except ImportError:
    HAS_ML = False

# Attempt to import CVE database
try:
    from Libraries.Chains.Generator.CVEDB.integration import CVEDatabaseIntegration
    from Libraries.Chains.Generator.CVEDB.enhanced import get_enhanced_cve_database
    HAS_CVE_DB = True
except ImportError:
    HAS_CVE_DB = False

# Module logger
logger = logging.getLogger(__name__)

# Import submodules
from .subdomain_discoverer import SubdomainDiscoverer
from .crawler import SiteCrawler
from .classifier import URLClassifier
from .ml_integrator import MLIntegrator
from .cve_correlator import CVECorrelator

class SiteExplorer:
    """
    Main coordinator for site exploration, crawling, and vulnerability scanning.
    Orchestrates the entire process from subdomain discovery to vulnerability assessment.
    """
    
    def __init__(self, target: str, options: Dict = None):
        """
        Initialize the site explorer.
        
        Args:
            target: Target URL or domain
            options: Configuration options
        """
        self.target = target
        self.options = options or {}
        
        # Configure logging
        log_level = getattr(logging, self.options.get('log_level', 'INFO').upper())
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        
        # Extract base domain
        parsed = urlparse(self.target)
        if parsed.netloc:
            self.base_domain = parsed.netloc
        else:
            self.base_domain = self.target
            self.target = f"http://{self.target}"
        
        # Remove www prefix if present
        if self.base_domain.startswith('www.'):
            self.base_domain = self.base_domain[4:]
        
        # Setup components
        # Use the new SubdomainEnumerationAPI directly (preferred over SubdomainDiscoverer)
        if HAS_SUBDOMAIN_API:
            self.subdomain_enum_api = SubdomainEnumerationAPI(logger=self.logger)
            self.logger.info("Using SubdomainEnumerationAPI for subdomain discovery")
        else:
            # Fallback to legacy wrapper if API not available
            self.subdomain_enum_api = None
            self.logger.warning("SubdomainEnumerationAPI not available, using legacy SubdomainDiscoverer")
            
        # Keep backward compatibility wrapper for now
        self.subdomain_discoverer = SubdomainDiscoverer(self.base_domain, self.options, self.logger)
        
        self.crawler = SiteCrawler(self.options, self.logger)
        self.url_classifier = URLClassifier(self.logger)
        
        # Setup MLIntegrator with OpenVINO options
        if HAS_ML:
            # Add OpenVINO-specific options
            ml_options = self.options.copy()
            ml_options.update({
                'enable_openvino': self.options.get('enable_openvino', True),
                'enable_quantization': self.options.get('enable_quantization', True),
                'benchmark_mode': self.options.get('ml_benchmark_mode', False),
                'high_exploit_threshold': self.options.get('high_exploit_threshold', 0.75),
                'medium_exploit_threshold': self.options.get('medium_exploit_threshold', 0.45),
                'low_exploit_threshold': self.options.get('low_exploit_threshold', 0.25)
            })
            self.ml_integrator = MLIntegrator(ml_options, self.logger)
            if hasattr(self.ml_integrator, 'openvino_enabled') and self.ml_integrator.openvino_enabled:
                if self.ml_integrator.accelerator and self.ml_integrator.accelerator.is_npu_available():
                    self.logger.info(f"ML acceleration enabled with NPU: {self.ml_integrator.accelerator.get_active_device()}")
                else:
                    self.logger.info(f"ML acceleration enabled with device: {self.ml_integrator.accelerator.get_active_device() if self.ml_integrator.accelerator else 'CPU'}")
        else:
            self.ml_integrator = None
        
        # CVE Database integration
        self.cve_db = None
        self.cve_correlator = None
        if HAS_CVE_DB and self.options.get('use_cve_db', True):
            try:
                self.cve_db = get_enhanced_cve_database(auto_update=self.options.get('auto_update_cve', False))
                self.cve_correlator = CVECorrelator(self.cve_db, self.options, self.logger)
                self.logger.info("CVE Database integration initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize CVE Database: {e}")
        
        # Vulnerability correlation engine
        self.correlation_engine = VulnerabilityCorrelationEngine(self.logger)
        if self.cve_db:
            self.correlation_engine.set_cve_database(self.cve_db)
        
        # Results storage
        self.discovered_subdomains = set()
        self.active_subdomains = set()
        self.crawled_urls = set()
        self.discovered_endpoints = set()
        self.tech_stack = {}
        self.vulnerabilities = []
        self.vulnerability_chains = []
        
        self.logger.info(f"SiteExplorer initialized for target: {self.target}")

    async def run_exploration(self) -> Dict[str, Any]:
        """
        Run the full site exploration process.
        
        Returns:
            Dictionary with exploration results
        """
        start_time = time.time()
        self.logger.info(f"Starting full site exploration for {self.target}")
        
        # Phase 1: Pre-enumeration (subdomain discovery)
        if self.options.get('discover_subdomains', True):
            await self._phase_subdomain_discovery()
        else:
            self.active_subdomains = {self.target}
        
        # Phase 2: Crawling and concurrent enumeration
        results = await self._phase_crawling_and_enumeration()
        
        # Phase 3: Vulnerability scanning
        vulnerabilities = await self._phase_vulnerability_scanning(results)
        
        # Phase 4: Correlation and analysis
        analysis = await self._phase_correlation_and_analysis(vulnerabilities)
        
        # Generate final report
        execution_time = time.time() - start_time
        report = self._generate_report(execution_time)
        
        # Save results if requested
        if self.options.get('output_file'):
            self._save_results(report)
        
        self.logger.info(f"Site exploration completed in {execution_time:.2f} seconds")
        return report

    async def _phase_subdomain_discovery(self):
        """Run the subdomain discovery phase."""
        self.logger.info("Starting Phase 1: Subdomain Discovery")
        
        # Check if we can use the direct API
        if HAS_SUBDOMAIN_API and self.subdomain_enum_api:
            self.logger.info("Using SubdomainEnumerationAPI directly for discovery")
            
            # Determine which discovery methods to use
            methods = []
            if self.options.get('use_crtsh', True):
                methods.append('crtsh')
            if self.options.get('use_dns', True):
                methods.append('dns')
            if self.options.get('use_web_archive', True):
                methods.append('web_archive')
            if self.options.get('use_wordlist', True) and 'wordlist_path' in self.options:
                methods.append('wordlist')
            
            # Configure timeout
            timeout = self.options.get('timeout', 30)
            
            # Discover subdomains directly with API
            discovered_subdomains = await self.subdomain_enum_api.discover_subdomains(
                domain=self.base_domain,
                methods=methods,
                wordlist_path=self.options.get('wordlist_path'),
                timeout=timeout,
                max_threads=self.options.get('threads', 10)
            )
            
            self.discovered_subdomains = discovered_subdomains
            
            # Resolve discovered subdomains if requested
            if self.options.get('resolve_subdomains', True):
                # Use the API's DNS resolver utility
                from Libraries.SubdomainEnumeration.utils.dns_resolver import DNSResolver
                resolver = DNSResolver(timeout=timeout, logger=self.logger)
                subdomain_ips = await resolver.resolve_bulk(self.discovered_subdomains)
                self.active_subdomains = {subdomain for subdomain, ips in subdomain_ips.items() if ips}
            else:
                self.active_subdomains = self.discovered_subdomains.copy()
        else:
            # Fall back to the compatibility wrapper
            self.logger.info("Using compatibility wrapper for discovery")
            discovery_results = await self.subdomain_discoverer.run_discovery()
            self.discovered_subdomains = set(discovery_results['subdomains'])
            self.active_subdomains = set(discovery_results['active_subdomains'])
        
        # Apply limit if specified
        max_subdomains = self.options.get('max_subdomains', 500)
        if len(self.active_subdomains) > max_subdomains:
            self.logger.warning(f"Limiting active subdomains to {max_subdomains} (found {len(self.active_subdomains)})")
            self.active_subdomains = set(list(self.active_subdomains)[:max_subdomains])
        
        self.logger.info(f"Subdomain discovery complete. Found {len(self.discovered_subdomains)} subdomains, {len(self.active_subdomains)} active.")

    async def _phase_crawling_and_enumeration(self) -> Dict[str, Any]:
        """
        Run the crawling and enumeration phase concurrently.
        
        Returns:
            Dictionary with crawling and enumeration results
        """
        self.logger.info("Starting Phase 2: Crawling and Enumeration")
        
        # Group subdomains by classification
        classified_domains = {}
        for subdomain in self.active_subdomains:
            domain_url = f"http://{subdomain}" if not subdomain.startswith(('http://', 'https://')) else subdomain
            classification = self.url_classifier.classify_url(domain_url)
            if classification not in classified_domains:
                classified_domains[classification] = []
            classified_domains[classification].append(domain_url)
        
        # Crawl and enumerate each subdomain
        # We'll crawl high-value targets first, then others
        crawl_results = {}
        priority_order = ['high_value', 'standard', 'low_value']
        
        for priority in priority_order:
            if priority in classified_domains:
                domains = classified_domains[priority]
                self.logger.info(f"Crawling {len(domains)} {priority} domains")
                
                for domain in domains:
                    result = await self.crawler.crawl_site(domain)
                    crawl_results[domain] = result
                    self.crawled_urls.update(result['discovered_urls'])
                    self.tech_stack.update(result['tech_stack'])
        
        self.logger.info(f"Crawling and enumeration complete. Discovered {len(self.crawled_urls)} URLs.")
        return crawl_results

    async def _phase_vulnerability_scanning(self, crawl_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run the vulnerability scanning phase.
        
        Args:
            crawl_results: Results from the crawling phase
            
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info("Starting Phase 3: Vulnerability Scanning")
        
        all_vulnerabilities = []
        
        # Create scanner options from site explorer options
        scanner_options = {
            'max_depth': self.options.get('scan_depth', 3),
            'threads': self.options.get('scan_threads', 10),
            'timeout': self.options.get('scan_timeout', 30),
            'html_report': self.options.get('html_report', True),
        }
        
        if self.options.get('output_file'):
            scanner_options['output_file'] = self.options.get('output_file')
        
        # Scan each domain concurrently
        scan_tasks = []
        for domain, results in crawl_results.items():
            # Create a comprehensive scanner for each domain
            scanner = ComprehensiveScanner(domain, scanner_options, logger=self.logger)
            
            # If we have a CVE database, set it for the scanner
            if self.cve_db:
                scanner.cve_db = self.cve_db
            
            # Add the task
            scan_tasks.append(self._scan_domain(scanner, results))
        
        # Run all scans concurrently
        scan_results = await asyncio.gather(*scan_tasks)
        
        # Aggregate all vulnerabilities
        for result in scan_results:
            all_vulnerabilities.extend(result.get('vulnerabilities', []))
            self.vulnerability_chains.extend(result.get('vulnerability_chains', []))
        
        self.vulnerabilities = all_vulnerabilities
        self.logger.info(f"Vulnerability scanning complete. Found {len(all_vulnerabilities)} vulnerabilities and {len(self.vulnerability_chains)} chains.")
        
        return all_vulnerabilities

    async def _scan_domain(self, scanner: ComprehensiveScanner, crawl_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan a single domain for vulnerabilities.
        
        Args:
            scanner: Comprehensive scanner instance
            crawl_result: Results from crawling the domain
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Run the comprehensive scan
            result = scanner.run_comprehensive_scan()
            
            # Apply machine learning enhancement if available
            if self.ml_integrator and HAS_ML:
                # Add exploit probability prediction for each vulnerability before enhancement
                if hasattr(self.ml_integrator, 'predict_exploit_probability'):
                    for vuln in result.get('vulnerabilities', []):
                        if 'ml_exploitability' not in vuln:
                            vuln['ml_exploitability'] = self.ml_integrator.predict_exploit_probability(vuln)
                
                # Full ML enhancement with OpenVINO acceleration if available
                result = await self.ml_integrator.enhance_scan_results(result, crawl_result)
                
                # Extract hardware acceleration status
                hw_accelerated = hasattr(self.ml_integrator, 'openvino_enabled') and self.ml_integrator.openvino_enabled
                if hw_accelerated and not result.get('hardware_accelerated', False):
                    result['hardware_accelerated'] = True
                    result['acceleration_device'] = self.ml_integrator.accelerator.get_active_device() if self.ml_integrator.accelerator else 'CPU'
            
            return result
        except Exception as e:
            self.logger.error(f"Error scanning domain: {e}")
            return {'vulnerabilities': [], 'vulnerability_chains': []}

    async def _phase_correlation_and_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run the correlation and analysis phase.
        
        Args:
            vulnerabilities: List of discovered vulnerabilities
            
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("Starting Phase 4: Correlation and Analysis")
        
        # Prepare scan results for correlation
        scan_results = {
            'base': {'vulnerabilities': vulnerabilities},
            'tech_stack': self.tech_stack
        }
        
        # Correlate with CVE database if available
        if self.cve_correlator and HAS_CVE_DB:
            cve_findings = self.cve_correlator.correlate_findings(scan_results)
            vulnerabilities.extend(cve_findings)
        
        # Correlate findings to identify attack chains
        correlated_findings = self.correlation_engine.correlate_findings(scan_results)
        
        # Analyze attack surface
        attack_surface = self.correlation_engine.analyze_attack_surface({
            'vulnerabilities': vulnerabilities,
            'tech_stack': self.tech_stack
        })
        
        self.logger.info(f"Correlation and analysis complete. Identified {len(correlated_findings)} correlated findings.")
        
        return {
            'correlated_findings': correlated_findings,
            'attack_surface': attack_surface
        }

    def _generate_report(self, execution_time: float) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all findings.
        
        Args:
            execution_time: Total execution time in seconds
            
        Returns:
            Dictionary with comprehensive report
        """
        report = {
            'target': self.target,
            'base_domain': self.base_domain,
            'scan_date': datetime.now().isoformat(),
            'execution_time': execution_time,
            'stats': {
                'discovered_subdomains': len(self.discovered_subdomains),
                'active_subdomains': len(self.active_subdomains),
                'crawled_urls': len(self.crawled_urls),
                'vulnerabilities': len(self.vulnerabilities),
                'vulnerability_chains': len(self.vulnerability_chains)
            },
            'subdomains': list(self.discovered_subdomains),
            'active_subdomains': list(self.active_subdomains),
            'tech_stack': self.tech_stack,
            'vulnerabilities': self.vulnerabilities,
            'vulnerability_chains': self.vulnerability_chains,
        }
        
        return report

    def _save_results(self, report: Dict[str, Any]):
        """
        Save the results to a file.
        
        Args:
            report: Report data to save
        """
        output_file = self.options.get('output_file')
        if not output_file:
            return
            
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Saved scan results to {output_file}")
            
            # Generate HTML report if requested
            if self.options.get('html_report'):
                html_file = output_file.replace('.json', '.html')
                self._generate_html_report(report, html_file)
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

    def _generate_html_report(self, report: Dict[str, Any], html_file: str):
        """
        Generate an HTML report from the results.
        
        Args:
            report: Report data
            html_file: Output file path
        """
        try:
            # Simple HTML report generation
            # In a real implementation, we'd use a proper template engine
            with open(html_file, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Site Explorer Report - {report['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ background-color: #ffdddd; }}
        .high {{ background-color: #ffffcc; }}
        .medium {{ background-color: #e0f0ff; }}
        .low {{ background-color: #eeffee; }}
        .summary {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Site Explorer Comprehensive Report</h1>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {report['target']}</p>
        <p><strong>Scan Date:</strong> {report['scan_date']}</p>
        <p><strong>Execution Time:</strong> {report['execution_time']:.2f} seconds</p>
        <p><strong>Discovered Subdomains:</strong> {report['stats']['discovered_subdomains']}</p>
        <p><strong>Active Subdomains:</strong> {report['stats']['active_subdomains']}</p>
        <p><strong>Crawled URLs:</strong> {report['stats']['crawled_urls']}</p>
        <p><strong>Vulnerabilities:</strong> {report['stats']['vulnerabilities']}</p>
        <p><strong>Vulnerability Chains:</strong> {report['stats']['vulnerability_chains']}</p>
    </div>
    
    <h2>Technology Stack</h2>
    <table>
        <tr>
            <th>Technology</th>
            <th>Version</th>
        </tr>
        {"".join([f"<tr><td>{tech}</td><td>{version}</td></tr>" for tech, version in report['tech_stack'].items()])}
    </table>
    
    <h2>Active Subdomains</h2>
    <table>
        <tr>
            <th>Subdomain</th>
        </tr>
        {"".join([f"<tr><td>{subdomain}</td></tr>" for subdomain in report['active_subdomains']])}
    </table>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>URL</th>
            <th>Description</th>
        </tr>
        {"".join([f"<tr class='{vuln.get('severity', 'low')}'><td>{vuln.get('type', 'Unknown')}</td><td>{vuln.get('severity', 'low')}</td><td>{vuln.get('url', 'N/A')}</td><td>{vuln.get('description', 'No description')}</td></tr>" for vuln in report['vulnerabilities']])}
    </table>
    
    <h2>Vulnerability Chains</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Confidence</th>
        </tr>
        {"".join([f"<tr class='{chain.get('severity', 'low')}'><td>{chain.get('name', 'Unknown')}</td><td>{chain.get('severity', 'low')}</td><td>{chain.get('description', 'No description')}</td><td>{chain.get('confidence', 0) * 100:.1f}%</td></tr>" for chain in report['vulnerability_chains']])}
    </table>
</body>
</html>""")
                
            self.logger.info(f"Generated HTML report at {html_file}")
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
