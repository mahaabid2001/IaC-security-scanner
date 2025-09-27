import os
import sys
import argparse
import json
from pathlib import Path
from typing import List, Dict
import yaml

from ai_security_analyzer import AISecurityAnalyzer, Vulnerability, Severity

class SecurityScanner:
    def __init__(self, openai_api_key: str):
        self.analyzer = AISecurityAnalyzer(openai_api_key)
        self.supported_extensions = {
            '.yaml': 'kubernetes',
            '.yml': 'kubernetes', 
            '.tf': 'terraform',
            '.tfvars': 'terraform'
        }
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities"""
        
        if not file_path.exists():
            print(f"Error: File {file_path} does not exist")
            return []
            
        file_extension = file_path.suffix.lower()
        if file_extension not in self.supported_extensions:
            print(f"Skipping unsupported file: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            file_type = self.supported_extensions[file_extension]
            
            print(f"🔍 Analyzing {file_path} ({file_type})...")
            
            if file_type == 'kubernetes':
                vulnerabilities = self.analyzer.analyze_kubernetes_file(content, str(file_path))
            else:  # terraform
                vulnerabilities = self.analyzer.analyze_terraform_file(content, str(file_path))
                
            return vulnerabilities
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return []
    
    def scan_directory(self, directory: Path, recursive: bool = True) -> Dict[str, List[Vulnerability]]:
        """Scan directory for vulnerable files"""
        
        results = {}
        
        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"
            
        for file_path in directory.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in self.supported_extensions:
                vulnerabilities = self.scan_file(file_path)
                if vulnerabilities:
                    results[str(file_path)] = vulnerabilities
                    
        return results
    
    def print_summary(self, results: Dict[str, List[Vulnerability]]):
        """Print vulnerability summary"""
        
        if not results:
            print("✅ No vulnerabilities found!")
            return
            
        total_vulns = sum(len(vulns) for vulns in results.values())
        severity_counts = {severity: 0 for severity in Severity}
        
        for vulnerabilities in results.values():
            for vuln in vulnerabilities:
                severity_counts[vuln.severity] += 1
        
        print(f"\n📊 SECURITY SCAN SUMMARY")
        print("=" * 50)
        print(f"Files scanned: {len(results)}")
        print(f"Total vulnerabilities: {total_vulns}")
        print(f"Critical: {severity_counts[Severity.CRITICAL]}")
        print(f"High: {severity_counts[Severity.HIGH]}")
        print(f"Medium: {severity_counts[Severity.MEDIUM]}")
        print(f"Low: {severity_counts[Severity.LOW]}")
        print(f"Info: {severity_counts[Severity.INFO]}")
    
    def print_detailed_results(self, results: Dict[str, List[Vulnerability]]):
        """Print detailed vulnerability information"""
        
        for file_path, vulnerabilities in results.items():
            print(f"\n📄 FILE: {file_path}")
            print("-" * (len(file_path) + 8))
            
            # Sort by severity (Critical first)
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.index(v.severity))
            
            for vuln in sorted_vulns:
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠", 
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                    Severity.INFO: "⚪"
                }
                
                print(f"\n{severity_emoji[vuln.severity]} {vuln.id}: {vuln.title}")
                print(f"   Severity: {vuln.severity.value}")
                print(f"   Category: {vuln.category}")
                print(f"   Resource: {vuln.affected_resource}")
                if vuln.line_number:
                    print(f"   Line: {vuln.line_number}")
                print(f"   Description: {vuln.description}")
                
                print(f"\n   🔧 REMEDIATION:")
                print(f"   {vuln.remediation}")
                
                if vuln.code_fix:
                    print(f"\n   💾 CODE FIX:")
                    # Indent the code fix
                    code_lines = vuln.code_fix.split('\n')
                    for line in code_lines:
                        print(f"   {line}")
                
                if vuln.references:
                    print(f"\n   📚 REFERENCES:")
                    for ref in vuln.references:
                        print(f"   - {ref}")
    
    def export_json(self, results: Dict[str, List[Vulnerability]], output_file: Path):
        """Export results to JSON file"""
        
        json_results = {}
        for file_path, vulnerabilities in results.items():
            json_results[file_path] = [
                {
                    'id': vuln.id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity.value,
                    'category': vuln.category,
                    'affected_resource': vuln.affected_resource,
                    'line_number': vuln.line_number,
                    'remediation': vuln.remediation,
                    'code_fix': vuln.code_fix,
                    'references': vuln.references
                }
                for vuln in vulnerabilities
            ]
        
        with open(output_file, 'w') as f:
            json.dump(json_results, f, indent=2)
        
        print(f"📄 Results exported to {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='AI-Powered Security Scanner for Kubernetes and Terraform files'
    )
    
    parser.add_argument(
        'path',
        help='File or directory to scan'
    )
    
    parser.add_argument(
        '--api-key',
        help='OpenAI API key (or set OPENAI_API_KEY env var)',
        default=os.getenv('OPENAI_API_KEY')
    )
    
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively scan directories'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only show summary, not detailed results'
    )
    
    parser.add_argument(
        '--severity-filter',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
        help='Only show vulnerabilities of this severity or higher'
    )
    
    args = parser.parse_args()
    
    # Validate API key
    if not args.api_key:
        print("Error: OpenAI API key required. Set OPENAI_API_KEY environment variable or use --api-key")
        sys.exit(1)
    
    # Initialize scanner
    scanner = SecurityScanner(args.api_key)
    
    # Determine if path is file or directory
    scan_path = Path(args.path)
    
    if scan_path.is_file():
        vulnerabilities = scanner.scan_file(scan_path)
        results = {str(scan_path): vulnerabilities} if vulnerabilities else {}
    elif scan_path.is_dir():
        results = scanner.scan_directory(scan_path, args.recursive)
    else:
        print(f"Error: Path {scan_path} does not exist")
        sys.exit(1)
    
    # Filter by severity if specified
    if args.severity_filter:
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_severity_idx = severity_order.index(args.severity_filter)
        
        filtered_results = {}
        for file_path, vulns in results.items():
            filtered_vulns = [
                v for v in vulns 
                if severity_order.index(v.severity.value) >= min_severity_idx
            ]
            if filtered_vulns:
                filtered_results[file_path] = filtered_vulns
        results = filtered_results
    
    # Print results
    scanner.print_summary(results)
    
    if not args.quiet and results:
        scanner.print_detailed_results(results)
    
    # Export if requested
    if args.output:
        scanner.export_json(results, Path(args.output))
    
    # Exit with error code if critical or high severity vulns found
    has_critical = any(
        vuln.severity in [Severity.CRITICAL, Severity.HIGH]
        for vulns in results.values()
        for vuln in vulns
    )
    
    if has_critical:
        sys.exit(1)

if __name__ == "__main__":
    main()