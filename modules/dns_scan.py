#!/usr/bin/env python3
import dns.resolver
import dns.query
import dns.zone
import socket
import concurrent.futures
import time
import logging
from typing import List, Dict, Set, Optional
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DNSScanner:
    def __init__(self, target_domain: str):
        self.domain = target_domain
        self.results = {
            'ip': None,
            'reverse_dns': None,
            'dns_records': {},
            'wildcard_detected': False,
            'zone_transfer': None,
            'subdomains': [],
            'errors': [],
            'mx_records': [],
            'cname_records': [],
            'txt_records': [],
            'ptr_records': [],
            'ns_records': [],
            'soa_record': None,
            'srv_records': [],
            'https_records': [],
            'caa_records': [],
            'ds_records': [],
            'sshfp_records': [],
            'tlsa_records': [],
            'spf_records': [],
            'ttl_info': {}
        }
        self.common_subdomains = [
            "www", "mail", "ftp", "dev", "test", "api", "admin", 
            "portal", "vpn", "beta", "stage", "cpanel", "webmail",
            "ns1", "ns2", "blog", "shop", "cdn", "img", "static",
            "support", "docs", "wiki", "files", "backup", "data",
            "db", "mysql", "postgresql", "redis", "elasticsearch",
            "kibana", "grafana", "prometheus", "alertmanager",
            "vault", "consul", "minio", "s3", "gcs", "azure"
        ]
        self.dns_record_types = [
            "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", 
            "SRV", "PTR", "DS", "CAA", "NSEC", "NSEC3", "DNSKEY",
            "RRSIG", "HTTPS", "SVCB", "HINFO", "RP", "AFSDB",
            "CERT", "DHCID", "DLV", "EUI48", "EUI64", "GPOS",
            "ISDN", "LOC", "MF", "MR", "MX", "NAPTR", "NSAP",
            "NSAP-PTR", "NULL", "OPENPGPKEY", "OPT", "PX", "RT",
            "SIG", "SMIMEA", "SPF", "SSHFP", "TLSA", "URI", "X25"
        ]
        self.timeout = 5  # Default timeout in seconds
    
    def scan_all(self) -> Dict:
        """Run all DNS scans in parallel"""
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._get_ip): "IP Resolution",
                executor.submit(self._dns_records): "DNS Records Enumeration",
                executor.submit(self._wildcard_test): "Wildcard Test",
                executor.submit(self._subdomain_enum): "Subdomain Enumeration",
                executor.submit(self._zone_transfer): "Zone Transfer Test",
                executor.submit(self._mx_records): "MX Records",
                executor.submit(self._cname_records): "CNAME Records",
                executor.submit(self._txt_records): "TXT Records",
                executor.submit(self._ns_records): "NS Records",
                executor.submit(self._soa_record): "SOA Record",
                executor.submit(self._srv_records): "SRV Records",
                executor.submit(self._caa_records): "CAA Records",
                executor.submit(self._spf_records): "SPF Records",
                executor.submit(self._ttl_info): "TTL Information"
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in {futures[future]}: {str(e)}")
                    self.results['errors'].append(str(e))
        
        duration = time.time() - start_time
        logger.info(f"Scan completed in {duration:.2f} seconds")
        return self.results
    
    def _get_ip(self) -> bool:
        """Get IP address and reverse DNS lookup"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['ip'] = ip
            
            try:
                reverse = socket.gethostbyaddr(ip)
                self.results['reverse_dns'] = reverse[0]
            except socket.herror:
                logger.warning(f"No reverse DNS found for {ip}")
                
            return True
        except socket.gaierror:
            logger.error(f"Could not resolve IP for {self.domain}")
            return False
    
    def _dns_records(self) -> bool:
        """Enumerate various DNS records"""
        for record_type in self.dns_record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, lifetime=self.timeout)
                self.results['dns_records'][record_type] = [
                    r.to_text() for r in answers
                ]
            except dns.resolver.NoAnswer:
                pass  # No records of this type
            except Exception as e:
                logger.error(f"Error resolving {record_type}: {str(e)}")
        
        return True
    
    def _wildcard_test(self) -> bool:
        """Test for wildcard DNS configuration"""
        test = f"randomtest123.{self.domain}"
        try:
            ip = socket.gethostbyname(test)
            self.results['wildcard_detected'] = True
            logger.info(f"Wildcard DNS detected: {test} -> {ip}")
            return True
        except socket.gaierror:
            logger.debug(f"No wildcard DNS for {test}")
            return False
    
    def _subdomain_enum(self) -> bool:
        """Enumerate common subdomains"""
        def resolve(subdomain):
            target = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(target)
                self.results['subdomains'].append((target, ip))
                logger.debug(f"Found: {target} -> {ip}")
            except socket.gaierror:
                pass  # Subdomain doesn't exist
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            executor.map(resolve, self.common_subdomains)
        
        return True
    
    def _zone_transfer(self) -> bool:
        """Attempt zone transfer from nameservers"""
        try:
            ns_records = dns.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            ns_list = [str(ns).rstrip(".") for ns in ns_records]
            
            for ns in ns_list:
                logger.info(f"Testing zone transfer against {ns}")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns, self.domain, timeout=self.timeout)
                    )
                    self.results['zone_transfer'] = {
                        'nameserver': ns,
                        'records': list(zone.nodes.keys()),
                        'status': 'allowed'
                    }
                    logger.info(f"Zone transfer successful from {ns}")
                    return True
                except Exception as e:
                    logger.debug(f"Zone transfer failed from {ns}: {str(e)}")
            
            self.results['zone_transfer'] = {'status': 'refused'}
            return False
        except Exception as e:
            logger.error(f"Error querying NS: {str(e)}")
            return False
    
    def _mx_records(self) -> bool:
        """Parse MX records"""
        try:
            mx_answers = dns.resolver.resolve(self.domain, "MX", lifetime=self.timeout)
            for mx in mx_answers:
                self.results['mx_records'].append({
                    'priority': mx.preference,
                    'exchange': str(mx.exchange).rstrip(".")
                })
        except Exception as e:
            logger.error(f"Error getting MX records: {str(e)}")
        return True
    
    def _cname_records(self) -> bool:
        """Parse CNAME records"""
        try:
            cname_answers = dns.resolver.resolve(self.domain, "CNAME", lifetime=self.timeout)
            for cname in cname_answers:
                self.results['cname_records'].append(str(cname.target).rstrip("."))
        except Exception as e:
            logger.error(f"Error getting CNAME records: {str(e)}")
        return True
    
    def _txt_records(self) -> bool:
        """Parse TXT records"""
        try:
            txt_answers = dns.resolver.resolve(self.domain, "TXT", lifetime=self.timeout)
            for txt in txt_answers:
                self.results['txt_records'].append(txt.to_text())
        except Exception as e:
            logger.error(f"Error getting TXT records: {str(e)}")
        return True
    
    def _ns_records(self) -> bool:
        """Parse NS records"""
        try:
            ns_answers = dns.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            for ns in ns_answers:
                self.results['ns_records'].append(str(ns.target).rstrip("."))
        except Exception as e:
            logger.error(f"Error getting NS records: {str(e)}")
        return True
    
    def _soa_record(self) -> bool:
        """Parse SOA record"""
        try:
            soa_answers = dns.resolver.resolve(self.domain, "SOA", lifetime=self.timeout)
            for soa in soa_answers:
                self.results['soa_record'] = {
                    'mname': str(soa.mname).rstrip("."),
                    'rname': str(soa.rname).rstrip("."),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum
                }
        except Exception as e:
            logger.error(f"Error getting SOA record: {str(e)}")
        return True
    
    def _srv_records(self) -> bool:
        """Parse SRV records"""
        try:
            srv_answers = dns.resolver.resolve(self.domain, "SRV", lifetime=self.timeout)
            for srv in srv_answers:
                self.results['srv_records'].append({
                    'priority': srv.priority,
                    'weight': srv.weight,
                    'port': srv.port,
                    'target': str(srv.target).rstrip(".")
                })
        except Exception as e:
            logger.error(f"Error getting SRV records: {str(e)}")
        return True
    
    def _caa_records(self) -> bool:
        """Parse CAA records"""
        try:
            caa_answers = dns.resolver.resolve(self.domain, "CAA", lifetime=self.timeout)
            for caa in caa_answers:
                self.results['caa_records'].append({
                    'flags': caa.flags,
                    'tag': caa.tag,
                    'value': caa.value
                })
        except Exception as e:
            logger.error(f"Error getting CAA records: {str(e)}")
        return True
    
    def _spf_records(self) -> bool:
        """Parse SPF records"""
        try:
            spf_answers = dns.resolver.resolve(self.domain, "SPF", lifetime=self.timeout)
            for spf in spf_answers:
                self.results['spf_records'].append(spf.to_text())
        except Exception as e:
            logger.error(f"Error getting SPF records: {str(e)}")
        return True
    
    def _ttl_info(self) -> bool:
        """Collect TTL information for A/AAAA records"""
        try:
            a_records = dns.resolver.resolve(self.domain, "A", lifetime=self.timeout)
            for record in a_records:
                ttl = record.ttl
                if ttl not in self.results['ttl_info']:
                    self.results['ttl_info'][ttl] = 0
                self.results['ttl_info'][ttl] += 1
                
            aaaa_records = dns.resolver.resolve(self.domain, "AAAA", lifetime=self.timeout)
            for record in aaaa_records:
                ttl = record.ttl
                if ttl not in self.results['ttl_info']:
                    self.results['ttl_info'][ttl] = 0
                self.results['ttl_info'][ttl] += 1
                
        except Exception as e:
            logger.error(f"Error collecting TTL info: {str(e)}")
        return True

def scan_dns(domain):
    """Wrapper function for backwards compatibility"""
    scanner = DNSScanner(domain)
    return scanner.scan_all()

def print_results(results: Dict):
    """Print formatted results"""
    print("\nDNS SCANNER RESULTS")
    print("="*70)
    
    print("\n[IP RESOLUTION]")
    if results['ip']:
        print(f"Domain: {results['domain']}")
        print(f"IP: {results['ip']}")
        if results['reverse_dns']:
            print(f"Reverse DNS: {results['reverse_dns']}")
    else:
        print("IP resolution failed")
    
    print("\n[DNS RECORDS]")
    for record_type, records in results['dns_records'].items():
        if records:
            print(f"\n{record_type} records:")
            for record in records:
                print(f"  {record}")
    
    print("\n[MX RECORDS]")
    if results['mx_records']:
        for mx in results['mx_records']:
            print(f"  Priority: {mx['priority']} | Exchange: {mx['exchange']}")
    else:
        print("No MX records found")
    
    print("\n[CNAME RECORDS]")
    if results['cname_records']:
        for cname in results['cname_records']:
            print(f"  {cname}")
    else:
        print("No CNAME records found")
    
    print("\n[TXT RECORDS]")
    if results['txt_records']:
        for txt in results['txt_records']:
            print(f"  {txt}")
    else:
        print("No TXT records found")
    
    print("\n[NS RECORDS]")
    if results['ns_records']:
        for ns in results['ns_records']:
            print(f"  {ns}")
    else:
        print("No NS records found")
    
    print("\n[SOA RECORD]")
    if results['soa_record']:
        soa = results['soa_record']
        print(f"  MNAME: {soa['mname']}")
        print(f"  RNAME: {soa['rname']}")
        print(f"  SERIAL: {soa['serial']}")
        print(f"  REFRESH: {soa['refresh']}")
        print(f"  RETRY: {soa['retry']}")
        print(f"  EXPIRE: {soa['expire']}")
        print(f"  MINIMUM: {soa['minimum']}")
    else:
        print("No SOA record found")
    
    print("\n[SRV RECORDS]")
    if results['srv_records']:
        for srv in results['srv_records']:
            print(f"  Priority: {srv['priority']}, Weight: {srv['weight']}, Port: {srv['port']}, Target: {srv['target']}")
    else:
        print("No SRV records found")
    
    print("\n[CAA RECORDS]")
    if results['caa_records']:
        for caa in results['caa_records']:
            print(f"  Flags: {caa['flags']}, Tag: {caa['tag']}, Value: {caa['value']}")
    else:
        print("No CAA records found")
    
    print("\n[SPF RECORDS]")
    if results['spf_records']:
        for spf in results['spf_records']:
            print(f"  {spf}")
    else:
        print("No SPF records found")
    
    print("\n[WILDCARD DNS]")
    print("Detected" if results['wildcard_detected'] else "Not detected")
    
    print("\n[SUBDOMAINS]")
    if results['subdomains']:
        for subdomain, ip in results['subdomains']:
            print(f"  {subdomain} -> {ip}")
    else:
        print("No subdomains found")
    
    print("\n[ZONE TRANSFER]")
    if results['zone_transfer']:
        status = results['zone_transfer']['status']
        if status == 'allowed':
            print(f"Zone transfer allowed from {results['zone_transfer']['nameserver']}")
            print(f"Records found: {len(results['zone_transfer']['records'])}")
        else:
            print("Zone transfer refused")
    else:
        print("Zone transfer test failed")
    
    print("\n[TTL INFORMATION]")
    if results['ttl_info']:
        print("TTL distribution:")
        for ttl, count in sorted(results['ttl_info'].items()):
            print(f"  {ttl}s: {count} records")
    else:
        print("No TTL information available")
    
    if results['errors']:
        print("\n[ERRORS]")
        for error in results['errors']:
            print(f"  {error}")

def main():
    parser = argparse.ArgumentParser(description='Advanced DNS Scanner')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=40, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds')
    args = parser.parse_args()
    
    scanner = DNSScanner(args.domain)
    scanner.timeout = args.timeout
    results = scanner.scan_all()
    print_results(results)

if __name__ == "__main__":
    main()

# Export the function for plascoy.py
__all__ = ['scan_dns', '_zone_transfer']
