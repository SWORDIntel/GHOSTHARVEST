#!/usr/bin/env python3
"""
Enhanced SiteCrawler with OpenVINO NPU Acceleration
---------------------------------------------------
Advanced web crawler with AI-powered analysis using Intel NPU:
- Content classification using BERT models on NPU
- Intelligent crawl prioritization with ML
- Visual content analysis for screenshots
- Advanced pattern recognition for security analysis
- Parallel processing with hardware acceleration
"""

import os
import sys
import json
import time
import logging
import asyncio
import aiohttp
import numpy as np
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from typing import Dict, List, Set, Any, Optional, Tuple, Union
import re
from bs4 import BeautifulSoup
from datetime import datetime
import random
import hashlib
from collections import defaultdict, deque
import aiofiles
from dataclasses import dataclass, field
from enum import Enum
import mimetypes
from concurrent.futures import ThreadPoolExecutor
import pickle

# OpenVINO imports for NPU acceleration
try:
    from openvino.runtime import Core, Type, Layout, PartialShape
    from openvino.preprocess import PrePostProcessor, ResizeAlgorithm
    from openvino.runtime import AsyncInferQueue
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False
    logging.warning("OpenVINO not available - NPU acceleration disabled")

# Import for image processing if analyzing visual content
try:
    import cv2
    from PIL import Image
    import io
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logging.warning("OpenCV/PIL not available - visual analysis disabled")

# Import transformers for text processing
try:
    from transformers import AutoTokenizer, AutoModel
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers not available - advanced text analysis disabled")

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import existing HTTP scanner
from Libraries.banner_scanner.http_scanner import EnhancedHTTPScanner, TECHNOLOGY_SIGNATURES


class CrawlPriority(Enum):
    """Priority levels for URL crawling"""
    CRITICAL = 1  # Security-sensitive endpoints
    HIGH = 2      # Authentication, admin panels
    MEDIUM = 3    # Forms, user data
    LOW = 4       # Standard pages
    MINIMAL = 5   # Static resources


@dataclass
class CrawlTask:
    """Represents a crawl task with priority"""
    url: str
    depth: int
    priority: CrawlPriority
    parent_url: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    def __lt__(self, other):
        """Compare tasks by priority and timestamp"""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.timestamp < other.timestamp


@dataclass
class PageAnalysis:
    """Comprehensive page analysis results"""
    url: str
    content_classification: Dict[str, float]
    security_score: float
    vulnerability_indicators: List[str]
    sensitive_data_found: List[Dict[str, Any]]
    ai_insights: Dict[str, Any]
    visual_analysis: Optional[Dict[str, Any]] = None


class NPUAccelerator:
    """
    Handles NPU acceleration for AI models using OpenVINO
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.ie = None
        self.text_classifier = None
        self.image_analyzer = None
        self.pattern_detector = None
        
        if OPENVINO_AVAILABLE:
            self._initialize_openvino()
    
    def _initialize_openvino(self):
        """Initialize OpenVINO runtime and load models"""
        try:
            self.ie = Core()
            
            # Check for NPU availability
            available_devices = self.ie.available_devices
            self.logger.info(f"Available devices: {available_devices}")
            
            # Prefer NPU if available, fallback to GPU or CPU
            if "NPU" in available_devices:
                self.device = "NPU"
                self.logger.info("Using NPU for acceleration")
            elif "GPU" in available_devices:
                self.device = "GPU"
                self.logger.info("NPU not available, using GPU")
            else:
                self.device = "CPU"
                self.logger.info("NPU/GPU not available, using CPU")
            
            # Load models for different tasks
            self._load_models()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize OpenVINO: {str(e)}")
            self.device = None
    
    def _load_models(self):
        """Load pre-trained models optimized for NPU"""
        model_dir = Path(__file__).parent / "models"
        
        # Text classification model (BERT-based)
        text_model_path = model_dir / "text_classifier.xml"
        if text_model_path.exists():
            try:
                model = self.ie.read_model(str(text_model_path))
                
                # Configure preprocessing
                ppp = PrePostProcessor(model)
                ppp.input().tensor() \
                    .set_element_type(Type.f32) \
                    .set_layout(Layout("NC"))
                
                model = ppp.build()
                self.text_classifier = self.ie.compile_model(model, self.device)
                self.logger.info(f"Loaded text classifier on {self.device}")
                
            except Exception as e:
                self.logger.warning(f"Failed to load text classifier: {str(e)}")
        
        # Image analysis model
        if CV2_AVAILABLE:
            image_model_path = model_dir / "image_analyzer.xml"
            if image_model_path.exists():
                try:
                    model = self.ie.read_model(str(image_model_path))
                    self.image_analyzer = self.ie.compile_model(model, self.device)
                    self.logger.info(f"Loaded image analyzer on {self.device}")
                except Exception as e:
                    self.logger.warning(f"Failed to load image analyzer: {str(e)}")
    
    async def classify_text(self, text: str) -> Dict[str, float]:
        """
        Classify text content using NPU-accelerated model
        
        Args:
            text: Text to classify
            
        Returns:
            Classification scores
        """
        if not self.text_classifier:
            return {"unknown": 1.0}
        
        try:
            # Tokenize and prepare input
            # This is a simplified example - in production, use proper tokenization
            tokens = text.encode('utf-8')[:512]  # Limit to 512 tokens
            input_data = np.array([tokens], dtype=np.float32)
            
            # Run inference
            infer_request = self.text_classifier.create_infer_request()
            input_tensor = infer_request.get_input_tensor()
            input_tensor.data[:] = input_data
            
            # Async inference for better performance
            infer_request.start_async()
            infer_request.wait()
            
            # Get results
            output = infer_request.get_output_tensor().data
            
            # Map to categories
            categories = [
                "sensitive_data", "authentication", "financial",
                "personal_info", "technical", "general"
            ]
            
            scores = {}
            for i, cat in enumerate(categories):
                if i < len(output[0]):
                    scores[cat] = float(output[0][i])
                    
            return scores
            
        except Exception as e:
            self.logger.error(f"Text classification error: {str(e)}")
            return {"error": 1.0}
    
    async def analyze_image(self, image_data: bytes) -> Dict[str, Any]:
        """
        Analyze image content using NPU
        
        Args:
            image_data: Image bytes
            
        Returns:
            Analysis results
        """
        if not self.image_analyzer or not CV2_AVAILABLE:
            return {"analyzed": False}
        
        try:
            # Decode image
            nparr = np.frombuffer(image_data, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is None:
                return {"analyzed": False, "error": "Failed to decode image"}
            
            # Resize for model input
            img_resized = cv2.resize(img, (224, 224))
            img_input = img_resized.transpose((2, 0, 1))  # CHW format
            img_input = np.expand_dims(img_input, axis=0).astype(np.float32)
            
            # Run inference
            infer_request = self.image_analyzer.create_infer_request()
            infer_request.infer({0: img_input})
            
            # Get results
            output = infer_request.get_output_tensor(0).data
            
            return {
                "analyzed": True,
                "contains_text": bool(output[0][0] > 0.5),
                "has_forms": bool(output[0][1] > 0.5),
                "security_relevant": bool(output[0][2] > 0.5),
                "confidence": float(np.max(output))
            }
            
        except Exception as e:
            self.logger.error(f"Image analysis error: {str(e)}")
            return {"analyzed": False, "error": str(e)}


class SecurityAnalyzer:
    """
    Advanced security analysis for crawled content
    """
    
    def __init__(self, logger):
        self.logger = logger
        
        # Security patterns
        self.sensitive_patterns = {
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'),
            'password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']+)'),
            'token': re.compile(r'(?i)(token|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'),
            'secret': re.compile(r'(?i)(secret|private[_-]?key)\s*[:=]\s*["\']?([^\s"\']+)'),
            'database': re.compile(r'(?i)(db_|database_|mysql_|postgres_|mongo_)(user|password|host|url)\s*[:=]\s*["\']?([^\s"\']+)'),
            'aws': re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?([^\s"\']+)'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        }
        
        # Vulnerability indicators
        self.vuln_patterns = {
            'sql_injection': re.compile(r'(?i)(select\s+.*\s+from|union\s+select|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table)'),
            'xss': re.compile(r'(?i)(<script|javascript:|onerror=|onload=|onclick=|<iframe|<object|<embed)'),
            'path_traversal': re.compile(r'\.\.\/|\.\.\\\\'),
            'command_injection': re.compile(r'(?i)(exec\(|system\(|eval\(|passthru\(|shell_exec\()'),
            'xxe': re.compile(r'(?i)(!DOCTYPE|!ENTITY|SYSTEM\s+"file:)'),
            'code_execution': re.compile(r'(?i)(eval|exec|compile|__import__|subprocess|os\.system)'),
        }
        
    def analyze_content(self, content: str, url: str) -> Dict[str, Any]:
        """
        Perform security analysis on content
        
        Args:
            content: Content to analyze
            url: URL of the content
            
        Returns:
            Security analysis results
        """
        results = {
            'sensitive_data': [],
            'vulnerabilities': [],
            'security_score': 100.0,
            'risk_level': 'low'
        }
        
        # Check for sensitive data
        for data_type, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(content)
            if matches:
                for match in matches[:5]:  # Limit to 5 matches per type
                    results['sensitive_data'].append({
                        'type': data_type,
                        'match': match if isinstance(match, str) else match[0],
                        'url': url
                    })
                results['security_score'] -= 10
        
        # Check for vulnerability patterns
        for vuln_type, pattern in self.vuln_patterns.items():
            if pattern.search(content):
                results['vulnerabilities'].append({
                    'type': vuln_type,
                    'url': url,
                    'confidence': 'high' if content.count(pattern.pattern) > 3 else 'medium'
                })
                results['security_score'] -= 15
        
        # Determine risk level
        if results['security_score'] < 40:
            results['risk_level'] = 'critical'
        elif results['security_score'] < 60:
            results['risk_level'] = 'high'
        elif results['security_score'] < 80:
            results['risk_level'] = 'medium'
        
        return results


class EnhancedSiteCrawler:
    """
    Enhanced site crawler with NPU acceleration and advanced features
    """
    
    def __init__(self, options: Dict = None, logger=None):
        """Initialize enhanced crawler"""
        self.options = options or {}
        self.logger = logger or logging.getLogger(__name__)
        
        # Enhanced configuration
        self.max_depth = self.options.get('max_depth', 5)
        self.max_pages = self.options.get('max_pages', 2000)
        self.max_retries = self.options.get('max_retries', 3)
        self.timeout = self.options.get('timeout', 30)
        self.concurrent_requests = self.options.get('concurrent_requests', 10)
        self.delay_range = self.options.get('delay_range', (0.5, 2.0))  # Random delay range
        self.respect_robots = self.options.get('respect_robots', True)
        self.follow_redirects = self.options.get('follow_redirects', True)
        self.verify_ssl = self.options.get('verify_ssl', False)
        self.max_size = self.options.get('max_size', 20 * 1024 * 1024)  # 20MB
        self.enable_npu = self.options.get('enable_npu', True) and OPENVINO_AVAILABLE
        self.capture_screenshots = self.options.get('capture_screenshots', False) and CV2_AVAILABLE
        
        # Initialize components
        self.npu_accelerator = NPUAccelerator(self.logger) if self.enable_npu else None
        self.security_analyzer = SecurityAnalyzer(self.logger)
        
        # Enhanced tracking
        self.visited_hashes = set()  # Track by content hash to avoid duplicate content
        self.url_patterns = defaultdict(int)  # Track URL patterns
        self.response_times = defaultdict(list)  # Track response times per domain
        self.error_counts = defaultdict(int)  # Track errors per domain
        self.redirect_chains = {}  # Track redirect chains
        
        # Priority queue for intelligent crawling
        self.crawl_queue = asyncio.PriorityQueue()
        
        # Results storage
        self.crawl_results = {
            'pages': [],
            'endpoints': defaultdict(list),
            'forms': {},
            'technologies': {},
            'security_findings': [],
            'ai_insights': {},
            'statistics': {}
        }
        
        # Session management with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=self.concurrent_requests,
            limit_per_host=5,
            ttl_dns_cache=300
        )
        
        # User agent rotation with realistic patterns
        self.user_agents = [
            # Chrome on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Firefox on Linux
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            # Safari on macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            # Edge on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            # Chrome on Android
            'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        ]
        
        # Initialize HTTP scanner
        self.http_scanner = EnhancedHTTPScanner(verify_tls=self.verify_ssl)
        
        # Thread pool for CPU-intensive tasks
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(connector=self.connector)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.session.close()
        self.thread_pool.shutdown()
        
    def _calculate_url_priority(self, url: str, parent_data: Optional[Dict] = None) -> CrawlPriority:
        """
        Calculate crawl priority for a URL based on various factors
        
        Args:
            url: URL to evaluate
            parent_data: Data from parent page
            
        Returns:
            Crawl priority
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Critical priority patterns
        critical_patterns = [
            r'/admin', r'/api/', r'/\.git', r'/config', r'/\.env',
            r'/backup', r'/database', r'/phpmyadmin', r'/wp-admin'
        ]
        if any(re.search(pattern, path) for pattern in critical_patterns):
            return CrawlPriority.CRITICAL
            
        # High priority patterns
        high_patterns = [
            r'/login', r'/auth', r'/signin', r'/register',
            r'/user', r'/account', r'/dashboard', r'/panel'
        ]
        if any(re.search(pattern, path) for pattern in high_patterns):
            return CrawlPriority.HIGH
            
        # Medium priority patterns
        medium_patterns = [
            r'/form', r'/submit', r'/upload', r'/download',
            r'/search', r'/contact', r'/profile'
        ]
        if any(re.search(pattern, path) for pattern in medium_patterns):
            return CrawlPriority.MEDIUM
            
        # Low priority for static resources
        static_extensions = ['.js', '.css', '.jpg', '.png', '.gif', '.ico', '.woff']
        if any(path.endswith(ext) for ext in static_extensions):
            return CrawlPriority.MINIMAL
            
        # Use AI classification if available
        if parent_data and self.npu_accelerator:
            # Check parent page AI insights
            ai_insights = parent_data.get('ai_insights', {})
            if ai_insights.get('security_score', 0) > 0.7:
                return CrawlPriority.HIGH
                
        return CrawlPriority.LOW
        
    def _get_content_hash(self, content: str) -> str:
        """Generate hash of content to detect duplicates"""
        # Normalize content by removing dynamic elements
        normalized = re.sub(r'\s+', ' ', content)
        normalized = re.sub(r'[0-9a-f]{32,}', 'HASH', normalized)  # Remove hashes
        normalized = re.sub(r'\d{10,}', 'TIMESTAMP', normalized)    # Remove timestamps
        
        return hashlib.sha256(normalized.encode()).hexdigest()
        
    async def _intelligent_delay(self, domain: str):
        """
        Implement intelligent delay based on domain response patterns
        
        Args:
            domain: Domain to calculate delay for
        """
        # Base delay with randomization
        min_delay, max_delay = self.delay_range
        delay = random.uniform(min_delay, max_delay)
        
        # Adjust based on response times
        if domain in self.response_times:
            avg_response = np.mean(self.response_times[domain][-10:])
            if avg_response > 2.0:  # Slow server
                delay *= 1.5
            elif avg_response < 0.5:  # Fast server
                delay *= 0.8
                
        # Adjust based on error rate
        if self.error_counts[domain] > 5:
            delay *= 2.0
            
        await asyncio.sleep(delay)
        
    async def _fetch_with_retry(self, url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """
        Fetch URL with intelligent retry mechanism
        
        Args:
            url: URL to fetch
            session: aiohttp session
            
        Returns:
            Response data or None
        """
        domain = urlparse(url).netloc
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                    ssl=False if not self.verify_ssl else None
                ) as response:
                    
                    # Track response time
                    response_time = time.time() - start_time
                    self.response_times[domain].append(response_time)
                    
                    # Handle redirects manually to track chains
                    if response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location')
                        if location:
                            # Track redirect chain
                            if url not in self.redirect_chains:
                                self.redirect_chains[url] = []
                            self.redirect_chains[url].append(location)
                            
                            if self.follow_redirects and len(self.redirect_chains.get(url, [])) < 10:
                                # Follow redirect
                                return await self._fetch_with_retry(urljoin(url, location), session)
                    
                    # Check content size
                    content_length = response.headers.get('Content-Length')
                    if content_length and int(content_length) > self.max_size:
                        self.logger.warning(f"Content too large for {url}: {content_length} bytes")
                        return None
                        
                    # Read content
                    content = await response.read()
                    text = content.decode('utf-8', errors='ignore')
                    
                    return {
                        'url': str(response.url),
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content': text,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(content),
                        'response_time': response_time,
                        'redirect_chain': self.redirect_chains.get(url, [])
                    }
                    
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout for {url} (attempt {attempt + 1}/{self.max_retries})")
                self.error_counts[domain] += 1
                
            except Exception as e:
                self.logger.warning(f"Error fetching {url}: {str(e)} (attempt {attempt + 1}/{self.max_retries})")
                self.error_counts[domain] += 1
                
            # Exponential backoff
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                
        return None
        
    async def _analyze_page(self, url: str, response_data: Dict[str, Any]) -> PageAnalysis:
        """
        Perform comprehensive page analysis using AI
        
        Args:
            url: Page URL
            response_data: Response data
            
        Returns:
            Page analysis results
        """
        content = response_data.get('content', '')
        
        # Basic security analysis
        security_analysis = self.security_analyzer.analyze_content(content, url)
        
        # AI-powered content classification
        ai_insights = {}
        if self.npu_accelerator:
            # Classify content
            content_classification = await self.npu_accelerator.classify_text(content[:5000])
            ai_insights['content_classification'] = content_classification
            
            # Calculate security score based on AI analysis
            security_relevant_score = sum([
                content_classification.get('sensitive_data', 0) * 0.3,
                content_classification.get('authentication', 0) * 0.3,
                content_classification.get('financial', 0) * 0.2,
                content_classification.get('personal_info', 0) * 0.2
            ])
            ai_insights['security_score'] = security_relevant_score
            
        # Visual analysis for screenshots
        visual_analysis = None
        if self.capture_screenshots and response_data.get('content_type', '').startswith('text/html'):
            # This would require a headless browser integration
            # Placeholder for visual analysis results
            visual_analysis = {
                'screenshot_taken': False,
                'reason': 'Feature requires headless browser integration'
            }
            
        return PageAnalysis(
            url=url,
            content_classification=ai_insights.get('content_classification', {}),
            security_score=security_analysis['security_score'],
            vulnerability_indicators=security_analysis['vulnerabilities'],
            sensitive_data_found=security_analysis['sensitive_data'],
            ai_insights=ai_insights,
            visual_analysis=visual_analysis
        )
        
    async def _process_page(self, task: CrawlTask) -> Optional[Dict[str, Any]]:
        """
        Process a single page with comprehensive analysis
        
        Args:
            task: Crawl task
            
        Returns:
            Processed page data
        """
        url = task.url
        
        # Check if already visited by content hash
        self.logger.debug(f"Processing {url} (depth: {task.depth}, priority: {task.priority.name})")
        
        # Fetch page
        response_data = await self._fetch_with_retry(url, self.session)
        if not response_data:
            return None
            
        # Check for duplicate content
        content_hash = self._get_content_hash(response_data['content'])
        if content_hash in self.visited_hashes:
            self.logger.debug(f"Duplicate content detected for {url}")
            return None
        self.visited_hashes.add(content_hash)
        
        # Parse HTML content
        extracted_data = {
            'url': url,
            'depth': task.depth,
            'parent_url': task.parent_url,
            'priority': task.priority.name,
            'timestamp': datetime.now().isoformat(),
            'response': response_data,
            'links': [],
            'forms': [],
            'resources': [],
            'metadata': {}
        }
        
        if 'text/html' in response_data.get('content_type', ''):
            soup = BeautifulSoup(response_data['content'], 'html.parser')
            
            # Extract title and meta information
            title_tag = soup.find('title')
            extracted_data['title'] = title_tag.text.strip() if title_tag else ''
            
            # Extract metadata
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property', '')
                content = meta.get('content', '')
                if name and content:
                    extracted_data['metadata'][name] = content
                    
            # Extract links with context
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for link in soup.find_all('a', href=True):
                href = link['href'].strip()
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    full_url = urljoin(url, href)
                    
                    # Extract link context
                    link_text = link.text.strip()
                    link_context = {
                        'url': full_url,
                        'text': link_text,
                        'title': link.get('title', ''),
                        'rel': link.get('rel', []),
                        'target': link.get('target', '')
                    }
                    extracted_data['links'].append(link_context)
                    
                    # Add to crawl queue if not external
                    if urlparse(base_url).netloc == urlparse(full_url).netloc:
                        if task.depth < self.max_depth:
                            priority = self._calculate_url_priority(full_url, extracted_data)
                            new_task = CrawlTask(
                                url=full_url,
                                depth=task.depth + 1,
                                priority=priority,
                                parent_url=url
                            )
                            await self.crawl_queue.put(new_task)
                            
            # Extract forms with detailed analysis
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'inputs': [],
                    'security_features': {
                        'csrf_token': False,
                        'captcha': False,
                        'honeypot': False
                    }
                }
                
                # Analyze form inputs
                for input_elem in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_elem.get('type', 'text')
                    input_name = input_elem.get('name', '')
                    
                    if input_name:
                        input_info = {
                            'name': input_name,
                            'type': input_type,
                            'required': input_elem.get('required') is not None,
                            'pattern': input_elem.get('pattern', ''),
                            'placeholder': input_elem.get('placeholder', ''),
                            'value': input_elem.get('value', '') if input_type != 'password' else '[REDACTED]'
                        }
                        form_data['inputs'].append(input_info)
                        
                        # Check for security features
                        if 'csrf' in input_name.lower() or 'token' in input_name.lower():
                            form_data['security_features']['csrf_token'] = True
                        if 'captcha' in input_name.lower():
                            form_data['security_features']['captcha'] = True
                        if input_type == 'hidden' and not input_elem.get('value'):
                            form_data['security_features']['honeypot'] = True
                            
                extracted_data['forms'].append(form_data)
                self.crawl_results['forms'][f"{url}:{form_data['action']}"] = form_data
                
            # Extract resources
            for tag, attr in [('script', 'src'), ('link', 'href'), ('img', 'src')]:
                for elem in soup.find_all(tag, **{attr: True}):
                    resource_url = urljoin(url, elem[attr])
                    resource_type = tag
                    if tag == 'link':
                        resource_type = elem.get('rel', ['stylesheet'])[0]
                    extracted_data['resources'].append({
                        'url': resource_url,
                        'type': resource_type
                    })
                    
        # Perform AI analysis
        page_analysis = await self._analyze_page(url, response_data)
        extracted_data['analysis'] = {
            'security_score': page_analysis.security_score,
            'vulnerabilities': page_analysis.vulnerability_indicators,
            'sensitive_data': page_analysis.sensitive_data_found,
            'ai_classification': page_analysis.content_classification,
            'ai_insights': page_analysis.ai_insights
        }
        
        # Categorize endpoint
        self._categorize_endpoint(extracted_data)
        
        # Update statistics
        self._update_statistics(extracted_data)
        
        # Store results
        self.crawl_results['pages'].append(extracted_data)
        
        # Store security findings
        if page_analysis.vulnerability_indicators or page_analysis.sensitive_data_found:
            self.crawl_results['security_findings'].append({
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'findings': page_analysis.vulnerability_indicators,
                'sensitive_data': page_analysis.sensitive_data_found,
                'risk_level': 'high' if page_analysis.security_score < 50 else 'medium'
            })
            
        return extracted_data
        
    def _categorize_endpoint(self, page_data: Dict[str, Any]):
        """Enhanced endpoint categorization with ML insights"""
        url = page_data['url']
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Use AI classification if available
        ai_classification = page_data.get('analysis', {}).get('ai_classification', {})
        
        # Determine primary category
        if ai_classification.get('authentication', 0) > 0.7 or '/auth' in path or '/login' in path:
            category = 'authentication'
        elif ai_classification.get('financial', 0) > 0.7 or '/payment' in path:
            category = 'financial'
        elif '/api/' in path or path.endswith(('.json', '.xml')):
            category = 'api'
        elif any(admin in path for admin in ['/admin', '/manage', '/dashboard']):
            category = 'admin'
        elif page_data.get('forms'):
            category = 'interactive'
        elif path.endswith(('.js', '.css', '.jpg', '.png', '.gif')):
            category = 'static'
        else:
            category = 'general'
            
        self.crawl_results['endpoints'][category].append({
            'url': url,
            'title': page_data.get('title', ''),
            'forms': len(page_data.get('forms', [])),
            'security_score': page_data.get('analysis', {}).get('security_score', 100)
        })
        
    def _update_statistics(self, page_data: Dict[str, Any]):
        """Update crawl statistics"""
        stats = self.crawl_results['statistics']
        
        # Response time statistics
        domain = urlparse(page_data['url']).netloc
        response_time = page_data['response']['response_time']
        
        if 'response_times' not in stats:
            stats['response_times'] = {}
        if domain not in stats['response_times']:
            stats['response_times'][domain] = []
        stats['response_times'][domain].append(response_time)
        
        # Content type statistics
        content_type = page_data['response']['content_type'].split(';')[0]
        if 'content_types' not in stats:
            stats['content_types'] = {}
        stats['content_types'][content_type] = stats['content_types'].get(content_type, 0) + 1
        
        # Status code statistics
        status_code = page_data['response']['status_code']
        if 'status_codes' not in stats:
            stats['status_codes'] = {}
        stats['status_codes'][str(status_code)] = stats['status_codes'].get(str(status_code), 0) + 1
        
    async def crawl(self, start_url: str) -> Dict[str, Any]:
        """
        Main crawl method with enhanced features
        
        Args:
            start_url: Starting URL for crawl
            
        Returns:
            Comprehensive crawl results
        """
        self.logger.info(f"Starting enhanced crawl of {start_url}")
        self.logger.info(f"NPU acceleration: {'Enabled' if self.enable_npu else 'Disabled'}")
        
        # Initialize crawl
        start_task = CrawlTask(
            url=start_url,
            depth=1,
            priority=CrawlPriority.CRITICAL
        )
        await self.crawl_queue.put(start_task)
        
        # Worker tasks
        workers = []
        for i in range(self.concurrent_requests):
            worker = asyncio.create_task(self._crawl_worker(f"Worker-{i}"))
            workers.append(worker)
            
        # Progress monitoring task
        monitor_task = asyncio.create_task(self._monitor_progress())
        
        # Wait for queue to be empty
        await self.crawl_queue.join()
        
        # Cancel workers
        for worker in workers:
            worker.cancel()
        monitor_task.cancel()
            
        # Wait for cancellation
        await asyncio.gather(*workers, monitor_task, return_exceptions=True)
        
        # Generate final report
        return self._generate_report()
        
    async def _crawl_worker(self, worker_name: str):
        """Worker task for processing crawl queue"""
        while True:
            try:
                # Get task from queue with timeout
                task = await asyncio.wait_for(self.crawl_queue.get(), timeout=10.0)
                
                # Check limits
                if len(self.crawl_results['pages']) >= self.max_pages:
                    self.logger.warning(f"{worker_name}: Reached page limit ({self.max_pages})")
                    self.crawl_queue.task_done()
                    continue
                    
                # Process page
                domain = urlparse(task.url).netloc
                await self._intelligent_delay(domain)
                
                await self._process_page(task)
                
                # Mark task as done
                self.crawl_queue.task_done()
                
            except asyncio.TimeoutError:
                # No more tasks in queue
                continue
            except asyncio.CancelledError:
                # Worker cancelled
                break
            except Exception as e:
                self.logger.error(f"{worker_name} error: {str(e)}")
                
    async def _monitor_progress(self):
        """Monitor and report crawl progress"""
        while True:
            try:
                await asyncio.sleep(5)
                
                pages_crawled = len(self.crawl_results['pages'])
                queue_size = self.crawl_queue.qsize()
                
                self.logger.info(
                    f"Progress: {pages_crawled} pages crawled, "
                    f"{queue_size} in queue, "
                    f"{len(self.crawl_results['security_findings'])} security findings"
                )
                
            except asyncio.CancelledError:
                break
                
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive crawl report"""
        report = {
            'summary': {
                'total_pages': len(self.crawl_results['pages']),
                'total_forms': len(self.crawl_results['forms']),
                'security_findings': len(self.crawl_results['security_findings']),
                'endpoint_categories': {k: len(v) for k, v in self.crawl_results['endpoints'].items()},
                'crawl_timestamp': datetime.now().isoformat()
            },
            'security_summary': {
                'critical_findings': sum(1 for f in self.crawl_results['security_findings'] if f['risk_level'] == 'critical'),
                'high_findings': sum(1 for f in self.crawl_results['security_findings'] if f['risk_level'] == 'high'),
                'medium_findings': sum(1 for f in self.crawl_results['security_findings'] if f['risk_level'] == 'medium'),
                'sensitive_data_types': list(set(
                    d['type'] for f in self.crawl_results['security_findings'] 
                    for d in f.get('sensitive_data', [])
                ))
            },
            'performance_metrics': {
                'average_response_times': {
                    domain: np.mean(times)
                    for domain, times in self.crawl_results['statistics'].get('response_times', {}).items()
                },
                'content_distribution': self.crawl_results['statistics'].get('content_types', {}),
                'status_codes': self.crawl_results['statistics'].get('status_codes', {})
            },
            'ai_insights': {
                'high_security_pages': [
                    {
                        'url': p['url'],
                        'security_score': p['analysis']['ai_insights'].get('security_score', 0)
                    }
                    for p in self.crawl_results['pages']
                    if p.get('analysis', {}).get('ai_insights', {}).get('security_score', 0) > 0.7
                ][:10]
            },
            'detailed_results': self.crawl_results
        }
        
        return report


# Example usage with terminal GUI
async def main():
    """Example usage with enhanced features"""
    import npyscreen
    
    class CrawlerConfigForm(npyscreen.Form):
        def create(self):
            self.url = self.add(npyscreen.TitleText, name='Target URL:', value='https://example.com')
            self.max_depth = self.add(npyscreen.TitleText, name='Max Depth:', value='3')
            self.max_pages = self.add(npyscreen.TitleText, name='Max Pages:', value='100')
            self.enable_npu = self.add(npyscreen.Checkbox, name='Enable NPU Acceleration', value=True)
            self.capture_screenshots = self.add(npyscreen.Checkbox, name='Capture Screenshots', value=False)
            
    class CrawlerApp(npyscreen.NPSAppManaged):
        def onStart(self):
            self.config_form = self.addForm('MAIN', CrawlerConfigForm, name='Enhanced Site Crawler Configuration')
            
    # Create GUI
    app = CrawlerApp()
    app.run()
    
    # Get configuration from form
    config = {
        'max_depth': int(app.config_form.max_depth.value),
        'max_pages': int(app.config_form.max_pages.value),
        'enable_npu': app.config_form.enable_npu.value,
        'capture_screenshots': app.config_form.capture_screenshots.value,
        'concurrent_requests': 10,
        'delay_range': (0.5, 2.0)
    }
    
    # Run crawler
    async with EnhancedSiteCrawler(options=config) as crawler:
        results = await crawler.crawl(app.config_form.url.value)
        
        # Save results
        output_file = f"crawl_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\nCrawl complete! Results saved to {output_file}")
        print(f"Found {results['summary']['total_pages']} pages")
        print(f"Discovered {results['summary']['security_findings']} security findings")
        print(f"Critical findings: {results['security_summary']['critical_findings']}")


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the crawler
    asyncio.run(main())