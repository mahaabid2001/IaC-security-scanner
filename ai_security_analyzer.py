
import json
import openai
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    affected_resource: str
    line_number: Optional[int]
    remediation: str
    code_fix: Optional[str]
    references: List[str]

class AISecurityAnalyzer:
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        
    def analyze_kubernetes_file(self, file_content: str, file_path: str) -> List[Vulnerability]:
        """Analyze Kubernetes YAML file for security vulnerabilities"""
        
        system_prompt = self._get_kubernetes_system_prompt()
        user_prompt = self._build_kubernetes_analysis_prompt(file_content, file_path)
        
        response = self._call_openai_api(system_prompt, user_prompt)
        return self._parse_vulnerability_response(response)
    
    def analyze_terraform_file(self, file_content: str, file_path: str) -> List[Vulnerability]:
        """Analyze Terraform HCL file for security vulnerabilities"""
        
        system_prompt = self._get_terraform_system_prompt()
        user_prompt = self._build_terraform_analysis_prompt(file_content, file_path)
        
        response = self._call_openai_api(system_prompt, user_prompt)
        return self._parse_vulnerability_response(response)
    
    def _get_kubernetes_system_prompt(self) -> str:
        return """You are a Kubernetes security expert specializing in container and cluster security analysis. 

Analyze the provided Kubernetes YAML configuration for security vulnerabilities and misconfigurations.

Focus on these critical security areas:
1. **Container Security**: Privileged containers, security contexts, capabilities
2. **RBAC & Access Control**: Service accounts, roles, cluster roles, bindings
3. **Network Security**: Network policies, service exposure, ingress configurations
4. **Resource Management**: Resource limits, quotas, admission controllers
5. **Secrets & ConfigMaps**: Sensitive data exposure, mounting practices
6. **Image Security**: Image sources, pull policies, vulnerability scanning
7. **Pod Security**: Security standards, admission controllers, policies

For each vulnerability found, provide:
- Unique ID (format: K8S-XXX)
- Clear title and description
- Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Security category
- Affected resource and location
- Detailed remediation steps
- Code fix example
- Relevant security references (CIS Kubernetes Benchmark, NIST, etc.)

Return response as valid JSON array of vulnerability objects. If no vulnerabilities found, return empty array."""

    def _get_terraform_system_prompt(self) -> str:
        return """You are a cloud infrastructure security expert specializing in Terraform security analysis.

Analyze the provided Terraform HCL configuration for security vulnerabilities and misconfigurations.

Focus on these critical security areas:
1. **Access Control**: IAM policies, roles, overly permissive permissions
2. **Network Security**: Security groups, NACLs, public access
3. **Data Protection**: Encryption at rest and in transit, key management
4. **Storage Security**: S3 buckets, database security, backup configurations
5. **Compute Security**: Instance configurations, SSH access, metadata service
6. **Logging & Monitoring**: CloudTrail, VPC Flow Logs, monitoring setup
7. **Compliance**: SOC2, PCI DSS, HIPAA requirements

For each vulnerability found, provide:
- Unique ID (format: TF-XXX)
- Clear title and description  
- Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Security category
- Affected resource and location
- Detailed remediation steps
- Code fix example
- Relevant security references (CIS Controls, AWS Security Best Practices, etc.)

Return response as valid JSON array of vulnerability objects. If no vulnerabilities found, return empty array."""

    def _build_kubernetes_analysis_prompt(self, file_content: str, file_path: str) -> str:
        return f"""Please analyze this Kubernetes configuration file for security vulnerabilities:

**File Path**: {file_path}

**Configuration Content**:
```yaml
{file_content}
```

**Analysis Requirements**:
1. Check for common Kubernetes security misconfigurations
2. Identify privilege escalation risks
3. Review network security settings
4. Validate resource constraints
5. Check for secrets handling issues
6. Assess RBAC configurations

**Response Format**:
Return a JSON array where each vulnerability object has this structure:
{{
  "id": "K8S-001",
  "title": "Brief vulnerability title",
  "description": "Detailed description of the security issue and its impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", 
  "category": "container_security|access_control|network|secrets|resources|images",
  "affected_resource": "Resource name and type",
  "line_number": 15,
  "remediation": "Step-by-step instructions to fix the vulnerability",
  "code_fix": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
  "references": ["https://kubernetes.io/docs/concepts/security/", "CIS Kubernetes Benchmark v1.6.0"]
}}

Analyze thoroughly and provide actionable remediation guidance."""

    def _build_terraform_analysis_prompt(self, file_content: str, file_path: str) -> str:
        return f"""Please analyze this Terraform configuration file for security vulnerabilities:

**File Path**: {file_path}

**Configuration Content**:
```hcl
{file_content}
```

**Analysis Requirements**:
1. Check for overly permissive IAM policies
2. Identify public access misconfigurations
3. Review encryption settings
4. Validate network security configurations
5. Check for credential exposure
6. Assess compliance with security frameworks

**Response Format**:
Return a JSON array where each vulnerability object has this structure:
{{
  "id": "TF-001",
  "title": "Brief vulnerability title",
  "description": "Detailed description of the security issue and its impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "access_control|network|encryption|storage|compute|logging",
  "affected_resource": "Resource name and type",
  "line_number": 25,
  "remediation": "Step-by-step instructions to fix the vulnerability",
  "code_fix": "server_side_encryption_configuration {{\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = \"AES256\"\n    }}\n  }}\n}}",
  "references": ["https://docs.aws.amazon.com/security/", "CIS Amazon Web Services Foundations Benchmark"]
}}

Analyze thoroughly and provide actionable remediation guidance."""

    def _call_openai_api(self, system_prompt: str, user_prompt: str) -> str:
        """Make API call to OpenAI with error handling and retry logic"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,  # Low temperature for consistent security analysis
                max_tokens=4000,  # Enough for detailed analysis
                response_format={"type": "json_object"}  # Ensure JSON response
            )
            
            return response.choices[0].message.content
            
        except openai.RateLimitError:
            print("Rate limit exceeded. Please wait and try again.")
            raise
        except openai.APIError as e:
            print(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            print(f"Unexpected error calling OpenAI API: {e}")
            raise

    def _parse_vulnerability_response(self, response_content: str) -> List[Vulnerability]:
        """Parse OpenAI response and convert to Vulnerability objects"""
        
        try:
            # Parse JSON response
            vulnerabilities_data = json.loads(response_content)
            
            # Handle case where response is wrapped in a key
            if isinstance(vulnerabilities_data, dict):
                if 'vulnerabilities' in vulnerabilities_data:
                    vulnerabilities_data = vulnerabilities_data['vulnerabilities']
                elif 'results' in vulnerabilities_data:
                    vulnerabilities_data = vulnerabilities_data['results']
                else:
                    # If it's a dict but not wrapped, convert to list
                    vulnerabilities_data = [vulnerabilities_data]
            
            vulnerabilities = []
            for vuln_data in vulnerabilities_data:
                try:
                    vulnerability = Vulnerability(
                        id=vuln_data.get('id', 'UNKNOWN'),
                        title=vuln_data.get('title', 'Unknown Vulnerability'),
                        description=vuln_data.get('description', ''),
                        severity=Severity(vuln_data.get('severity', 'MEDIUM')),
                        category=vuln_data.get('category', 'general'),
                        affected_resource=vuln_data.get('affected_resource', ''),
                        line_number=vuln_data.get('line_number'),
                        remediation=vuln_data.get('remediation', ''),
                        code_fix=vuln_data.get('code_fix'),
                        references=vuln_data.get('references', [])
                    )
                    vulnerabilities.append(vulnerability)
                except (KeyError, ValueError) as e:
                    print(f"Error parsing vulnerability: {e}")
                    continue
                    
            return vulnerabilities
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            print(f"Raw response: {response_content}")
            return []
        except Exception as e:
            print(f"Error processing vulnerabilities: {e}")
            return []

    def generate_detailed_remediation(self, vulnerability: Vulnerability, 
                                    file_content: str) -> str:
        """Generate detailed remediation steps for a specific vulnerability"""
        
        system_prompt = """You are a security remediation specialist. Provide detailed, 
step-by-step instructions to fix the specific vulnerability in the given configuration.

Include:
1. Exact code changes needed
2. Before/after examples
3. Verification steps
4. Additional security considerations
5. Alternative solutions if applicable"""

        user_prompt = f"""Provide detailed remediation for this vulnerability:

**Vulnerability**: {vulnerability.title}
**Description**: {vulnerability.description}
**Affected Resource**: {vulnerability.affected_resource}
**Current Code Fix**: {vulnerability.code_fix}

**Full File Content**:
```
{file_content}
```

Please provide comprehensive remediation steps with exact code examples."""

        response = self._call_openai_api(system_prompt, user_prompt)
        return response

# Example usage and testing
def example_usage():
    # Initialize the analyzer
    analyzer = AISecurityAnalyzer(api_key="your-openai-api-key")
    
    # Example Kubernetes file with vulnerabilities
    k8s_content = """
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
    ports:
    - containerPort: 80
    env:
    - name: DB_PASSWORD
      value: "hardcoded-secret"
"""

    # Example Terraform file with vulnerabilities  
    tf_content = """
resource "aws_s3_bucket" "example" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name_prefix = "web-"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

    # Analyze files
    print("Analyzing Kubernetes file...")
    k8s_vulns = analyzer.analyze_kubernetes_file(k8s_content, "pod.yaml")
    
    print("Analyzing Terraform file...")
    tf_vulns = analyzer.analyze_terraform_file(tf_content, "main.tf")
    
    # Print results
    print(f"\nFound {len(k8s_vulns)} Kubernetes vulnerabilities:")
    for vuln in k8s_vulns:
        print(f"- {vuln.id}: {vuln.title} ({vuln.severity.value})")
        
    print(f"\nFound {len(tf_vulns)} Terraform vulnerabilities:")
    for vuln in tf_vulns:
        print(f"- {vuln.id}: {vuln.title} ({vuln.severity.value})")

if __name__ == "__main__":
    example_usage()