#!/usr/bin/env python3
"""
SubdomainDiscoverer - Advanced subdomain enumeration module
-----------------------------------------------------------
Discovers subdomains using multiple techniques including:
- Certificate Transparency logs (crt.sh)
- DNS-based enumeration
- Web scraping
- OSINT sources
- Integration with existing Pre_Enumeration tools

IMPORTANT: This module is now a backward compatibility wrapper around the 
Libraries.SubdomainEnumeration package. For new code, you should use:

    from Libraries.SubdomainEnumeration.api import SubdomainEnumerationAPI

This wrapper is maintained for backward compatibility but will be deprecated
in a future release.
"""

import os
import sys
import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

# Add project root to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import the SubdomainEnumeration API
from Libraries.SubdomainEnumeration.api import SubdomainEnumerationAPI

# Attempt to import Pre_Enumeration tools for CAPHARVEST integration
try:
    from Pre_Enumeration.CAPHARVEST import CAPHarvester
    HAS_CAPHARVEST = True
except ImportError:
    HAS_CAPHARVEST = False

class SubdomainDiscoverer:
    """
    Discovers subdomains using multiple sources including crt.sh, DNS enumeration,
    and other techniques.
    
    This class is now a backward compatibility wrapper around the unified SubdomainEnumeration package.
    For new code, please use the Libraries.SubdomainEnumeration.api.SubdomainEnumerationAPI directly.
    """
    
    def __init__(self, base_domain: str, options: Dict = None, logger=None):
        """
        Initialize the subdomain discoverer.
        
        Args:
            base_domain: Base domain to discover subdomains for
            options: Configuration options
            logger: Optional logger instance
        """
        self.base_domain = base_domain
        self.options = options or {}
        self.logger = logger or logging.getLogger(__name__)
        self.subdomains = set()
        self.resolved_subdomains = set()
        
        # Configure timeout
        self.timeout = self.options.get('timeout', 30)
        
        # Configure maximum number of subdomains to return
        self.max_subdomains = self.options.get('max_subdomains', 500)
        
        # Initialize the SubdomainEnumerationAPI
        self.api = SubdomainEnumerationAPI(logger=self.logger)
        
    async def discover_from_crtsh(self) -> Set[str]:
        """
        Discover subdomains from Certificate Transparency logs using crt.sh.
        
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Discovering subdomains from crt.sh for {self.base_domain}")
        
        # Use the SubdomainEnumerationAPI to discover subdomains from Certificate Transparency logs
        try:
            subdomains = await self.api.discover_subdomains(
                domain=self.base_domain,
                methods=["crtsh"],
                timeout=self.timeout
            )
            
            self.logger.info(f"Discovered {len(subdomains)} subdomains from crt.sh")
            self.subdomains.update(subdomains)
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error retrieving subdomains from crt.sh: {str(e)}")
            return set()
    
    async def discover_from_dns(self) -> Set[str]:
        """
        Discover subdomains using DNS enumeration techniques.
        
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Discovering subdomains using DNS techniques for {self.base_domain}")
        
        try:
            # Directly use the API's DNS discovery method
            subdomains = await self.api.discover_subdomains(
                domain=self.base_domain,
                methods=["dns"],
                timeout=self.timeout
            )
            
            self.logger.info(f"Discovered {len(subdomains)} subdomains from DNS techniques")
            self.subdomains.update(subdomains)
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error retrieving subdomains from DNS: {str(e)}")
            return set()
    
    async def discover_from_capharvest(self) -> Set[str]:
        """
        Discover subdomains using CAPHARVEST (if available).
        
        Returns:
            Set of discovered subdomains
        """
        if not HAS_CAPHARVEST:
            self.logger.warning("CAPHARVEST module not available")
            return set()
            
        self.logger.info(f"Discovering subdomains using CAPHARVEST for {self.base_domain}")
        subdomains = set()
        
        try:
            # CAPHARVEST is not yet integrated into the SubdomainEnumeration package,
            # so we'll use the original implementation for now
            harvester = CAPHarvester(self.base_domain)
            results = harvester.harvest()
            
            # Process results
            for record in results:
                domain = record.get('domain', '')
                if domain and self.base_domain in domain and domain != self.base_domain:
                    subdomains.add(domain.strip())
                    
            self.logger.info(f"Discovered {len(subdomains)} subdomains from CAPHARVEST")
                    
        except Exception as e:
            self.logger.error(f"Error using CAPHARVEST: {str(e)}")
        
        self.subdomains.update(subdomains)
        return subdomains
    
    async def discover_from_web_archive(self) -> Set[str]:
        """
        Discover subdomains from the Web Archive.
        
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Discovering subdomains from Web Archive for {self.base_domain}")
        
        try:
            # Directly use the API's web_archive discovery strategy
            subdomains = await self.api.discover_subdomains(
                domain=self.base_domain,
                methods=["web_archive"],
                timeout=self.timeout
            )
            
            self.logger.info(f"Discovered {len(subdomains)} subdomains from Web Archive")
            self.subdomains.update(subdomains)
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error retrieving subdomains from Web Archive: {str(e)}")
            return set()
    
    async def resolve_subdomains(self) -> Set[str]:
        """
        Resolve discovered subdomains to validate they're active.
        
        Returns:
            Set of resolved subdomains
        """
        self.logger.info(f"Resolving {len(self.subdomains)} discovered subdomains")
        
        if not self.subdomains:
            self.logger.warning("No subdomains to resolve")
            return set()
        
        try:
            # Use the API's DNS resolver utility from Utils
            from Libraries.SubdomainEnumeration.utils.dns_resolver import DNSResolver
            
            # Create a resolver with the same timeout as the main class
            resolver = DNSResolver(timeout=self.timeout, logger=self.logger)
            
            # Resolve all subdomains in parallel using the API's resolver
            subdomain_ips = await resolver.resolve_bulk(self.subdomains)
            
            # Extract subdomains that resolved successfully (have at least one IP)
            resolved = {subdomain for subdomain, ips in subdomain_ips.items() if ips}
            
            self.logger.info(f"Successfully resolved {len(resolved)} subdomains")
            self.resolved_subdomains = resolved
            return resolved
            
        except Exception as e:
            self.logger.error(f"Error resolving subdomains: {str(e)}")
            return set()
    
    async def run_discovery(self) -> Dict[str, Any]:
        """
        Run the full subdomain discovery process.
        
        Returns:
            Dictionary with discovery results
        """
        self.logger.info(f"Starting subdomain discovery for {self.base_domain}")
        
        # Convert SubdomainDiscoverer options to SubdomainEnumerationAPI options
        api_options = {}
        
        # Map discovery methods
        methods = []
        if self.options.get('use_crtsh', True):
            methods.append('crtsh')
        if self.options.get('use_dns', True):
            methods.append('dns')
        if self.options.get('use_web_archive', True):
            methods.append('web_archive')
        if self.options.get('use_wordlist', True) and 'wordlist_path' in self.options:
            methods.append('wordlist')
        
        # Use CAPHARVEST separately as it's not in the new API
        use_capharvest = self.options.get('use_capharvest', True) and HAS_CAPHARVEST
        
        try:
            # First, run the main discovery with the API
            if methods:
                self.subdomains = await self.api.discover_subdomains(
                    domain=self.base_domain,
                    methods=methods,
                    wordlist_path=self.options.get('wordlist_path'),
                    timeout=self.timeout,
                    max_threads=self.options.get('threads', 10),
                    options=api_options
                )
                self.logger.info(f"Discovered {len(self.subdomains)} subdomains using {', '.join(methods)}")
            
            # Add CAPHARVEST results if requested
            if use_capharvest:
                self.logger.info("Adding CAPHARVEST results to discovery")
                capharvest_subdomains = await self.discover_from_capharvest()
                original_count = len(self.subdomains)
                self.subdomains.update(capharvest_subdomains)
                new_count = len(self.subdomains) - original_count
                if new_count > 0:
                    self.logger.info(f"CAPHARVEST added {new_count} unique subdomains")
            
            # Resolve discovered subdomains if requested
            if self.options.get('resolve_subdomains', True):
                await self.resolve_subdomains()
                active_subdomains = self.resolved_subdomains
            else:
                active_subdomains = self.subdomains
            
            # Limit the number of subdomains returned
            if len(active_subdomains) > self.max_subdomains:
                self.logger.warning(f"Limiting subdomains to {self.max_subdomains} (found {len(active_subdomains)})")
                active_subdomains = set(list(active_subdomains)[:self.max_subdomains])
            
            self.logger.info(f"Discovered {len(self.subdomains)} subdomains, {len(active_subdomains)} active")
            
            # Return a consistent result format
            return {
                'base_domain': self.base_domain,
                'total_discovered': len(self.subdomains),
                'total_active': len(active_subdomains),
                'subdomains': list(self.subdomains),
                'active_subdomains': list(active_subdomains)
            }
            
        except Exception as e:
            self.logger.error(f"Error during subdomain discovery: {str(e)}")
            return {
                'base_domain': self.base_domain,
                'total_discovered': 0,
                'total_active': 0,
                'subdomains': [],
                'active_subdomains': [],
                'error': str(e)
            }
