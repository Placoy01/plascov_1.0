#!/usr/bin/env python3
"""
Web Crawler - Discover endpoints, pages, and links
"""

import requests
from colorama import Fore, init
from urllib.parse import urljoin, urlparse
import re

init(autoreset=True)

class WebCrawler:
    """Simple web crawler for endpoint discovery"""
    
    def __init__(self, target, max_depth=2, max_pages=100):
        self.target = target
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.discovered_endpoints = set()
        self.forms = []
        self.scripts = []
        self.media = []
    
    def crawl(self):
        """Start crawling"""
        print(Fore.CYAN + "[CRAWLER] Starting crawl...")
        
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        self._crawl_recursive(self.target, depth=0)
        
        print(Fore.CYAN + "[CRAWLER] Crawl completed")
        return {
            'endpoints': list(self.discovered_endpoints),
            'forms': self.forms,
            'scripts': self.scripts,
            'media': self.media
        }
    
    def _crawl_recursive(self, url, depth):
        """Recursively crawl URLs"""
        
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        if url in self.visited:
            return
        
        self.visited.add(url)
        print(Fore.BLUE + f"[CRAWLER] Crawling: {url} (depth: {depth})")
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0'})
            session.verify = False
            
            response = session.get(url, timeout=10)
            
            if response.status_code != 200:
                return
            
            # Extract links
            link_pattern = r'href=["\']([^"\']+)'
            links = re.findall(link_pattern, response.text)
            
            for link in links:
                # Clean up link
                link = link.split('#')[0]  # Remove fragments
                
                if link.startswith('http'):
                    full_url = link
                elif link.startswith('/'):
                    base = self.target.split('?')[0].rsplit('/', 1)[0]
                    full_url = base + link
                else:
                    full_url = urljoin(url, link)
                
                # Check if same domain
                if urlparse(full_url).netloc == urlparse(self.target).netloc:
                    self.discovered_endpoints.add(full_url)
                    
                    # Continue crawling if within depth limit
                    if depth < self.max_depth and len(self.visited) < self.max_pages:
                        self._crawl_recursive(full_url, depth + 1)
            
            # Extract forms
            form_pattern = r'<form[^>]*action=["\']([^"\']+)'
            forms = re.findall(form_pattern, response.text)
            self.forms.extend(forms)
            
            # Extract scripts
            script_pattern = r'<script[^>]*src=["\']([^"\']+)'
            scripts = re.findall(script_pattern, response.text)
            self.scripts.extend(scripts)
            
            # Extract media (images, etc)
            img_pattern = r'<img[^>]*src=["\']([^"\']+)'
            images = re.findall(img_pattern, response.text)
            self.media.extend(images)
        
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[INFO] Timeout: {url}")
        except Exception as e:
            print(Fore.YELLOW + f"[INFO] Error crawling {url}: {e}")
    
    def get_summary(self):
        """Get crawl summary"""
        return {
            'total_pages': len(self.visited),
            'endpoints': len(self.discovered_endpoints),
            'forms': len(set(self.forms)),
            'scripts': len(set(self.scripts)),
            'media': len(set(self.media))
        }
    
    def print_results(self):
        """Print crawl results"""
        summary = self.get_summary()
        
        print(Fore.GREEN + f"\n[CRAWLER RESULTS]")
        print(Fore.BLUE + f"Pages crawled: {summary['total_pages']}")
        print(Fore.BLUE + f"Unique endpoints: {summary['endpoints']}")
        print(Fore.BLUE + f"Forms found: {summary['forms']}")
        print(Fore.BLUE + f"Scripts found: {summary['scripts']}")
        print(Fore.BLUE + f"Media files: {summary['media']}")
        
        if self.discovered_endpoints:
            print(Fore.GREEN + f"\n[ENDPOINTS] (first 20):")
            for endpoint in list(self.discovered_endpoints)[:20]:
                print(Fore.GREEN + f"  - {endpoint}")
        
        if self.forms:
            print(Fore.YELLOW + f"\n[FORMS]:")
            for form in list(set(self.forms))[:10]:
                print(Fore.YELLOW + f"  - {form}")
        
        if self.scripts:
            print(Fore.MAGENTA + f"\n[SCRIPTS]:")
            for script in list(set(self.scripts))[:10]:
                print(Fore.MAGENTA + f"  - {script}")

def crawl_website(target, max_depth=2, max_pages=100):
    """
    Crawl a website and discover endpoints
    """
    print(Fore.CYAN + "[WEB CRAWLER STARTED]")
    
    crawler = WebCrawler(target, max_depth=max_depth, max_pages=max_pages)
    results = crawler.crawl()
    crawler.print_results()
    
    print(Fore.CYAN + "[WEB CRAWLER COMPLETED]")
    return results
