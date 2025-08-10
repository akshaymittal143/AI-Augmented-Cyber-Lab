"""
Artifact Validation Component

Schema validation and format verification for cloud-native security artifacts.
Ensures artifact integrity before LLM analysis.
"""

import re
import yaml
import json
from datetime import datetime
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

from .analyzer import ArtifactType


@dataclass
class ValidationResult:
    """Result of artifact validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    metadata: Dict
    timestamp: datetime


class ArtifactValidator:
    """Validates cloud-native artifacts before security analysis."""
    
    def __init__(self):
        self.dockerfile_patterns = self._compile_dockerfile_patterns()
        self.kubernetes_required_fields = self._get_kubernetes_required_fields()
    
    def validate_artifact(
        self, 
        content: str, 
        artifact_type: ArtifactType
    ) -> ValidationResult:
        """
        Validate an artifact based on its type.
        
        Args:
            content: Raw artifact content
            artifact_type: Type of artifact to validate
            
        Returns:
            ValidationResult with validation status and details
        """
        errors = []
        warnings = []
        metadata = {}
        
        try:
            if artifact_type == ArtifactType.DOCKERFILE:
                errors, warnings, metadata = self._validate_dockerfile(content)
            elif artifact_type == ArtifactType.KUBERNETES_YAML:
                errors, warnings, metadata = self._validate_kubernetes_yaml(content)
            elif artifact_type == ArtifactType.TERRAFORM:
                errors, warnings, metadata = self._validate_terraform(content)
            elif artifact_type == ArtifactType.CICD_PIPELINE:
                errors, warnings, metadata = self._validate_cicd_pipeline(content)
            else:
                errors = [f"Unsupported artifact type: {artifact_type.value}"]
                
        except Exception as e:
            errors.append(f"Validation failed: {str(e)}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            metadata=metadata,
            timestamp=datetime.utcnow()
        )
    
    def _validate_dockerfile(self, content: str) -> tuple:
        """Validate Dockerfile format and basic structure."""
        errors = []
        warnings = []
        metadata = {}
        
        lines = content.strip().split('\n')
        metadata['line_count'] = len(lines)
        metadata['instruction_count'] = 0
        
        # Check for FROM instruction
        has_from = False
        from_line = None
        
        # Track instructions
        instructions = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Extract instruction
            parts = line.split(None, 1)
            if parts:
                instruction = parts[0].upper()
                instructions.append(instruction)
                metadata['instruction_count'] += 1
                
                # Check FROM instruction
                if instruction == 'FROM':
                    has_from = True
                    from_line = i
                    
                    if len(parts) > 1:
                        image = parts[1]
                        # Check for latest tag
                        if ':latest' in image or ':' not in image:
                            warnings.append(f"Line {i}: Consider pinning image version instead of using 'latest'")
        
        # Validation checks
        if not has_from:
            errors.append("Missing required FROM instruction")
        elif from_line != 1:
            warnings.append("FROM instruction should typically be first (excluding comments)")
        
        # Check for common security patterns
        has_user = 'USER' in instructions
        has_healthcheck = 'HEALTHCHECK' in instructions
        
        if not has_user:
            warnings.append("No USER instruction found - container may run as root")
        
        if not has_healthcheck:
            warnings.append("No HEALTHCHECK instruction - consider adding health monitoring")
        
        # Check for potential secrets in content
        secret_patterns = [
            r'(?i)(password|pwd|secret|key|token)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
            r'(?i)api[_-]?key\s*[:=]\s*[\'"][^\'"]+[\'"]'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content):
                warnings.append("Potential hardcoded secret detected")
                break
        
        metadata['instructions'] = instructions
        metadata['has_user_instruction'] = has_user
        
        return errors, warnings, metadata
    
    def _validate_kubernetes_yaml(self, content: str) -> tuple:
        """Validate Kubernetes YAML manifest."""
        errors = []
        warnings = []
        metadata = {}
        
        try:
            # Parse YAML
            documents = list(yaml.safe_load_all(content))
            metadata['document_count'] = len(documents)
            
            for i, doc in enumerate(documents):
                if not doc:
                    continue
                    
                doc_metadata = {}
                
                # Check required fields
                if 'apiVersion' not in doc:
                    errors.append(f"Document {i+1}: Missing 'apiVersion' field")
                else:
                    doc_metadata['api_version'] = doc['apiVersion']
                
                if 'kind' not in doc:
                    errors.append(f"Document {i+1}: Missing 'kind' field")
                else:
                    kind = doc['kind']
                    doc_metadata['kind'] = kind
                    
                    # Kind-specific validation
                    if kind == 'Pod' or kind == 'Deployment':
                        self._validate_pod_spec(doc, errors, warnings, i+1)
                    elif kind == 'Service':
                        self._validate_service_spec(doc, errors, warnings, i+1)
                    elif kind == 'NetworkPolicy':
                        self._validate_network_policy(doc, errors, warnings, i+1)
                
                if 'metadata' not in doc:
                    errors.append(f"Document {i+1}: Missing 'metadata' field")
                elif 'name' not in doc['metadata']:
                    errors.append(f"Document {i+1}: Missing 'metadata.name' field")
                
                metadata[f'document_{i+1}'] = doc_metadata
                
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML format: {str(e)}")
        except Exception as e:
            errors.append(f"YAML validation error: {str(e)}")
        
        return errors, warnings, metadata
    
    def _validate_pod_spec(self, doc: dict, errors: list, warnings: list, doc_num: int):
        """Validate Pod/Deployment security specifications."""
        spec = doc.get('spec', {})
        
        # For Deployment, get pod template spec
        if doc.get('kind') == 'Deployment':
            spec = spec.get('template', {}).get('spec', {})
        
        containers = spec.get('containers', [])
        if not containers:
            errors.append(f"Document {doc_num}: No containers defined")
            return
        
        for i, container in enumerate(containers):
            container_name = container.get('name', f'container-{i}')
            
            # Check security context
            security_context = container.get('securityContext', {})
            
            if security_context.get('privileged'):
                warnings.append(f"Document {doc_num}: Container '{container_name}' runs in privileged mode")
            
            if security_context.get('runAsUser') == 0:
                warnings.append(f"Document {doc_num}: Container '{container_name}' runs as root user")
            
            # Check resource limits
            resources = container.get('resources', {})
            if 'limits' not in resources:
                warnings.append(f"Document {doc_num}: Container '{container_name}' has no resource limits")
            
            # Check image
            image = container.get('image', '')
            if ':latest' in image or ':' not in image:
                warnings.append(f"Document {doc_num}: Container '{container_name}' uses 'latest' tag")
    
    def _validate_service_spec(self, doc: dict, errors: list, warnings: list, doc_num: int):
        """Validate Service security specifications."""
        spec = doc.get('spec', {})
        service_type = spec.get('type', 'ClusterIP')
        
        if service_type == 'LoadBalancer':
            warnings.append(f"Document {doc_num}: LoadBalancer service exposes workload externally")
        elif service_type == 'NodePort':
            warnings.append(f"Document {doc_num}: NodePort service exposes ports on all nodes")
    
    def _validate_network_policy(self, doc: dict, errors: list, warnings: list, doc_num: int):
        """Validate NetworkPolicy specifications."""
        spec = doc.get('spec', {})
        
        if 'podSelector' not in spec:
            errors.append(f"Document {doc_num}: NetworkPolicy missing 'podSelector'")
        
        # Check for overly permissive policies
        ingress = spec.get('ingress', [])
        egress = spec.get('egress', [])
        
        for rule in ingress:
            if not rule.get('from') and not rule.get('ports'):
                warnings.append(f"Document {doc_num}: Overly permissive ingress rule")
    
    def _validate_terraform(self, content: str) -> tuple:
        """Validate Terraform configuration."""
        errors = []
        warnings = []
        metadata = {}
        
        # Basic HCL syntax validation
        if not content.strip():
            errors.append("Empty Terraform configuration")
            return errors, warnings, metadata
        
        # Check for common patterns
        lines = content.split('\n')
        metadata['line_count'] = len(lines)
        
        # Look for resource blocks
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'
        resources = re.findall(resource_pattern, content)
        metadata['resource_count'] = len(resources)
        metadata['resource_types'] = list(set([r[0] for r in resources]))
        
        # Check for hardcoded secrets
        secret_patterns = [
            r'(?i)(password|secret|key|token)\s*=\s*"[^"]+"',
            r'(?i)access_key\s*=\s*"AKIA[0-9A-Z]{16}"'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content):
                warnings.append("Potential hardcoded credential detected")
                break
        
        return errors, warnings, metadata
    
    def _validate_cicd_pipeline(self, content: str) -> tuple:
        """Validate CI/CD pipeline configuration."""
        errors = []
        warnings = []
        metadata = {}
        
        try:
            # Try to parse as YAML (GitHub Actions, GitLab CI, etc.)
            config = yaml.safe_load(content)
            
            if isinstance(config, dict):
                metadata['pipeline_type'] = 'yaml'
                
                # Check for common CI/CD patterns
                if 'jobs' in config:  # GitHub Actions
                    metadata['platform'] = 'github-actions'
                    self._validate_github_actions(config, errors, warnings)
                elif 'stages' in config:  # GitLab CI
                    metadata['platform'] = 'gitlab-ci'
                    self._validate_gitlab_ci(config, errors, warnings)
                
        except yaml.YAMLError:
            # Try as JSON (some pipelines use JSON)
            try:
                config = json.loads(content)
                metadata['pipeline_type'] = 'json'
            except json.JSONDecodeError:
                errors.append("Invalid pipeline configuration format")
        
        return errors, warnings, metadata
    
    def _validate_github_actions(self, config: dict, errors: list, warnings: list):
        """Validate GitHub Actions workflow."""
        jobs = config.get('jobs', {})
        
        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])
            
            for step in steps:
                # Check for hardcoded secrets
                if isinstance(step, dict):
                    step_str = str(step)
                    if re.search(r'(?i)(password|token|key).*[:=].*["\'][^"\']+["\']', step_str):
                        warnings.append(f"Job '{job_name}': Potential hardcoded secret in step")
    
    def _validate_gitlab_ci(self, config: dict, errors: list, warnings: list):
        """Validate GitLab CI configuration."""
        stages = config.get('stages', [])
        if not stages:
            warnings.append("No stages defined in GitLab CI configuration")
    
    def _compile_dockerfile_patterns(self) -> dict:
        """Compile regex patterns for Dockerfile validation."""
        return {
            'instruction': re.compile(r'^([A-Z]+)\s+(.*)$'),
            'from': re.compile(r'^FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?$', re.IGNORECASE),
            'secret': re.compile(r'(?i)(password|secret|key|token)\s*[:=]\s*[\'"][^\'"]+[\'"]')
        }
    
    def _get_kubernetes_required_fields(self) -> dict:
        """Define required fields for different Kubernetes resources."""
        return {
            'Pod': ['apiVersion', 'kind', 'metadata', 'spec'],
            'Deployment': ['apiVersion', 'kind', 'metadata', 'spec'],
            'Service': ['apiVersion', 'kind', 'metadata', 'spec'],
            'ConfigMap': ['apiVersion', 'kind', 'metadata'],
            'Secret': ['apiVersion', 'kind', 'metadata'],
        }
