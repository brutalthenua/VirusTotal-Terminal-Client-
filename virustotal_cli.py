#!/usr/bin/env python3
"""
VirusTotal Terminal Client
A command-line interface for VirusTotal API v3
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

# Configuration
API_KEY = "      " # Replace with your actual VirusTotal API key
API_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "x-apikey": API_KEY,
    "User-Agent": "VirusTotal-CLI/1.0"
}


class VirusTotalClient:
    """VirusTotal API client"""
    
    def __init__(self, api_key: str = None):
        """Initialize the VirusTotal client"""
        if api_key:
            self.api_key = api_key
            HEADERS["x-apikey"] = api_key
        else:
            self.api_key = API_KEY
        
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
    
    def check_api_key(self) -> bool:
        """Check if API key is valid"""
        try:
            response = self.session.get(f"{API_BASE_URL}/me")
            return response.status_code == 200
        except:
            return False
    
    def get_file_hash(self, file_path: str) -> Tuple[str, str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            md5 = hashlib.md5(file_data).hexdigest()
            sha1 = hashlib.sha1(file_data).hexdigest()
            sha256 = hashlib.sha256(file_data).hexdigest()
            
            return md5, sha1, sha256
        except Exception as e:
            raise Exception(f"Error reading file: {e}")
    
    def upload_file(self, file_path: str) -> Dict:
        """Upload a file to VirusTotal for analysis"""
        try:
            if not os.path.exists(file_path):
                return {"error": "File not found"}
            
            file_size = os.path.getsize(file_path)
            
            # For large files, use upload URL method
            if file_size > 32 * 1024 * 1024:  # 32MB
                return self._upload_large_file(file_path)
            
            # For small files, use direct upload
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = self.session.post(
                    f"{API_BASE_URL}/files",
                    files=files
                )
            
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def _upload_large_file(self, file_path: str) -> Dict:
        """Upload large file using upload URL method"""
        try:
            # Get upload URL
            response = self.session.get(f"{API_BASE_URL}/files/upload_url")
            upload_url = response.json()['data']
            
            # Upload file
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = self.session.post(upload_url, files=files)
            
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_file_report(self, file_hash: str) -> Dict:
        """Get report for a file by its hash"""
        try:
            response = self.session.get(f"{API_BASE_URL}/files/{file_hash}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_url_report(self, url: str) -> Dict:
        """Get report for a URL"""
        try:
            # URL needs to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            response = self.session.get(f"{API_BASE_URL}/urls/{url_id}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def scan_url(self, url: str) -> Dict:
        """Submit a URL for scanning"""
        try:
            response = self.session.post(
                f"{API_BASE_URL}/urls",
                data={"url": url}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_ip_report(self, ip_address: str) -> Dict:
        """Get report for an IP address"""
        try:
            response = self.session.get(f"{API_BASE_URL}/ip_addresses/{ip_address}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_domain_report(self, domain: str) -> Dict:
        """Get report for a domain"""
        try:
            response = self.session.get(f"{API_BASE_URL}/domains/{domain}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_analysis_report(self, analysis_id: str) -> Dict:
        """Get analysis results by ID"""
        try:
            response = self.session.get(f"{API_BASE_URL}/analyses/{analysis_id}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class OutputFormatter:
    """Format and display results"""
    
    @staticmethod
    def print_file_hashes(file_path: str, md5: str, sha1: str, sha256: str):
        """Print file hashes"""
        print(f"\n📁 File: {file_path}")
        print(f"  MD5:    {md5}")
        print(f"  SHA1:   {sha1}")
        print(f"  SHA256: {sha256}")
        print("-" * 60)
    
    @staticmethod
    def print_file_report(report: Dict, file_path: str = None):
        """Print file analysis report"""
        if "error" in report:
            print(f"❌ Error: {report['error']}")
            return
        
        data = report.get('data', {}).get('attributes', {})
        
        if file_path:
            print(f"\n📊 Analysis Report for: {file_path}")
        else:
            print(f"\n📊 Analysis Report")
        
        print("-" * 60)
        
        # Basic info
        if 'meaningful_name' in data:
            print(f"Name: {data['meaningful_name']}")
        
        if 'last_analysis_stats' in data:
            stats = data['last_analysis_stats']
            total = sum(stats.values())
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            
            print(f"\n🔍 Detection Stats:")
            print(f"  Malicious:  {malicious}/{total}")
            print(f"  Suspicious: {suspicious}/{total}")
            print(f"  Undetected: {undetected}/{total}")
            
            # Detection ratio
            if total > 0:
                ratio = (malicious + suspicious) / total * 100
                print(f"  Threat Level: {ratio:.1f}%")
                
                if ratio > 50:
                    print("  ⚠️  HIGH RISK")
                elif ratio > 10:
                    print("  ⚠️  MEDIUM RISK")
                elif malicious > 0:
                    print("  ⚠️  LOW RISK")
                else:
                    print("  ✅ CLEAN")
        
        # File info
        if 'size' in data:
            print(f"\n📁 File Info:")
            print(f"  Size: {data['size']} bytes")
        
        if 'type_tag' in data:
            print(f"  Type: {data['type_tag']}")
        
        # Names
        if 'names' in data and data['names']:
            print(f"\n📝 Known Names:")
            for name in data['names'][:5]:  # Show only first 5
                print(f"  • {name}")
        
        # Malicious detections
        if 'last_analysis_results' in data:
            print(f"\n🔴 Malicious Detections:")
            vendors = data['last_analysis_results']
            malicious_found = False
            
            for vendor, result in vendors.items():
                if result['category'] == 'malicious':
                    malicious_found = True
                    print(f"  • {vendor}: {result.get('result', 'Malicious')}")
            
            if not malicious_found:
                print("  No malicious detections found")
        
        print("-" * 60)
    
    @staticmethod
    def print_url_report(report: Dict, url: str = None):
        """Print URL analysis report"""
        if "error" in report:
            print(f"❌ Error: {report['error']}")
            return
        
        data = report.get('data', {}).get('attributes', {})
        
        if url:
            print(f"\n🌐 URL Analysis: {url}")
        print("-" * 60)
        
        if 'last_analysis_stats' in data:
            stats = data['last_analysis_stats']
            total = sum(stats.values())
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            print(f"🔍 Detection Stats:")
            print(f"  Malicious:  {malicious}/{total}")
            print(f"  Suspicious: {suspicious}/{total}")
            
            if total > 0:
                ratio = (malicious + suspicious) / total * 100
                print(f"  Threat Level: {ratio:.1f}%")
        
        # Categories
        if 'categories' in data:
            print(f"\n📋 Categories:")
            for vendor, category in data['categories'].items():
                print(f"  • {vendor}: {category}")
        
        print("-" * 60)
    
    @staticmethod
    def print_ip_report(report: Dict, ip: str):
        """Print IP address report"""
        if "error" in report:
            print(f"❌ Error: {report['error']}")
            return
        
        data = report.get('data', {}).get('attributes', {})
        
        print(f"\n🌐 IP Analysis: {ip}")
        print("-" * 60)
        
        # Reputation
        if 'reputation' in data:
            rep = data['reputation']
            print(f"Reputation Score: {rep}")
        
        # Country
        if 'country' in data:
            print(f"Country: {data['country']}")
        
        # Analysis stats
        if 'last_analysis_stats' in data:
            stats = data['last_analysis_stats']
            print(f"\n🔍 Analysis Stats:")
            print(f"  Malicious:  {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
        
        # Detected URLs
        if 'last_analysis_results' in data:
            print(f"\n🔴 Detected URLs:")
            results = data['last_analysis_results']
            count = 0
            for vendor, result in results.items():
                if result['category'] == 'malicious':
                    count += 1
                    if count <= 5:  # Show only first 5
                        print(f"  • {vendor}: {result.get('result', 'Malicious')}")
            if count > 5:
                print(f"  ... and {count - 5} more")
        
        print("-" * 60)
    
    @staticmethod
    def print_domain_report(report: Dict, domain: str):
        """Print domain report"""
        if "error" in report:
            print(f"❌ Error: {report['error']}")
            return
        
        data = report.get('data', {}).get('attributes', {})
        
        print(f"\n🌐 Domain Analysis: {domain}")
        print("-" * 60)
        
        # Basic info
        if 'last_dns_records' in data:
            print(f"DNS Records:")
            for record in data['last_dns_records'][:3]:  # Show first 3
                print(f"  • {record.get('type', '')}: {record.get('value', '')}")
        
        # Analysis stats
        if 'last_analysis_stats' in data:
            stats = data['last_analysis_stats']
            print(f"\n🔍 Analysis Stats:")
            print(f"  Malicious:  {stats.get('malicious', 0)}")
            print(f"  Suspicious: {stats.get('suspicious', 0)}")
        
        print("-" * 60)
    
    @staticmethod
    def print_upload_result(result: Dict, file_path: str):
        """Print file upload result"""
        if "error" in result:
            print(f"❌ Upload error: {result['error']}")
            return
        
        data = result.get('data', {})
        print(f"\n✅ File uploaded successfully: {file_path}")
        print(f"📋 Analysis ID: {data.get('id', 'N/A')}")
        
        # Wait a moment and get the analysis
        print("⏳ Waiting for analysis to complete...")
        time.sleep(2)
    
    @staticmethod
    def save_report(report: Dict, filename: str = "virustotal_report.json"):
        """Save report to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"✅ Report saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="VirusTotal Terminal Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f suspicious.exe          # Analyze a file
  %(prog)s -u https://malicious.site  # Analyze a URL
  %(prog)s -i 8.8.8.8                 # Check IP address
  %(prog)s -d example.com             # Check domain
  %(prog)s -H sha256_hash             # Check file by hash
  %(prog)s -f file.exe -s             # Save report to JSON
  %(prog)s --hash-only file.exe       # Only show file hashes
        """
    )
    
    # Add arguments
    parser.add_argument("-f", "--file", help="Analyze a file")
    parser.add_argument("-u", "--url", help="Analyze a URL")
    parser.add_argument("-i", "--ip", help="Analyze an IP address")
    parser.add_argument("-d", "--domain", help="Analyze a domain")
    parser.add_argument("-H", "--hash", help="Analyze a file by hash (MD5, SHA1, or SHA256)")
    parser.add_argument("-s", "--save", action="store_true", help="Save report to JSON file")
    parser.add_argument("--hash-only", action="store_true", help="Only show file hashes (no upload)")
    parser.add_argument("-k", "--api-key", help="Specify VirusTotal API key")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Check if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    # Initialize client
    client = VirusTotalClient(args.api_key)
    
    # Check API key
    if not client.check_api_key():
        print("❌ Invalid or missing API key. Please set your VirusTotal API key:")
        print("1. Get your API key from: https://www.virustotal.com/gui/my-apikey")
        print("2. Replace 'YOUR_API_KEY_HERE' in the script or use -k option")
        sys.exit(1)
    
    formatter = OutputFormatter()
    
    # Handle file analysis
    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        
        # Calculate hashes
        try:
            md5, sha1, sha256 = client.get_file_hash(args.file)
            formatter.print_file_hashes(args.file, md5, sha1, sha256)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)
        
        if not args.hash_only:
            print("📤 Uploading file to VirusTotal...")
            upload_result = client.upload_file(args.file)
            
            if "error" not in upload_result:
                formatter.print_upload_result(upload_result, args.file)
                
                # Get analysis ID and wait for completion
                analysis_id = upload_result.get('data', {}).get('id', '')
                if analysis_id:
                    print("⏳ Waiting for analysis (this may take a minute)...")
                    
                    # Poll for analysis completion
                    for i in range(10):
                        time.sleep(10)  # Wait 10 seconds between checks
                        analysis_result = client.get_analysis_report(analysis_id)
                        status = analysis_result.get('data', {}).get('attributes', {}).get('status', '')
                        
                        if status == 'completed':
                            print("✅ Analysis completed!")
                            report = client.get_file_report(sha256)
                            formatter.print_file_report(report, args.file)
                            
                            if args.save:
                                filename = f"vt_report_{os.path.basename(args.file)}.json"
                                formatter.save_report(report, filename)
                            break
                        elif i == 9:
                            print("⚠️  Analysis taking longer than expected.")
                            print("   You can check later with:")
                            print(f"   {sys.argv[0]} -H {sha256}")
            else:
                print(f"❌ Upload failed: {upload_result.get('error')}")
    
    # Handle hash lookup
    elif args.hash:
        print(f"🔍 Looking up hash: {args.hash}")
        report = client.get_file_report(args.hash)
        formatter.print_file_report(report)
        
        if args.save:
            filename = f"vt_report_hash_{args.hash[:10]}.json"
            formatter.save_report(report, filename)
    
    # Handle URL analysis
    elif args.url:
        print(f"🔍 Analyzing URL: {args.url}")
        report = client.get_url_report(args.url)
        
        if "error" in report or report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) == 0:
            print("⚠️  No existing analysis found. Submitting for scanning...")
            scan_result = client.scan_url(args.url)
            if "error" not in scan_result:
                print("✅ URL submitted for scanning")
                analysis_id = scan_result.get('data', {}).get('id')
                time.sleep(5)  # Wait a bit
                report = client.get_url_report(args.url)
        
        formatter.print_url_report(report, args.url)
        
        if args.save:
            import base64
            url_id = base64.urlsafe_b64encode(args.url.encode()).decode().strip("=")
            filename = f"vt_report_url_{url_id[:10]}.json"
            formatter.save_report(report, filename)
    
    # Handle IP analysis
    elif args.ip:
        print(f"🔍 Analyzing IP: {args.ip}")
        report = client.get_ip_report(args.ip)
        formatter.print_ip_report(report, args.ip)
        
        if args.save:
            filename = f"vt_report_ip_{args.ip}.json"
            formatter.save_report(report, filename)
    
    # Handle domain analysis
    elif args.domain:
        print(f"🔍 Analyzing domain: {args.domain}")
        report = client.get_domain_report(args.domain)
        formatter.print_domain_report(report, args.domain)
        
        if args.save:
            filename = f"vt_report_domain_{args.domain}.json"
            formatter.save_report(report, filename)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
