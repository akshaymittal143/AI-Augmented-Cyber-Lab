"""
MITRE ATT&CK Framework Integration

Mapping of attack techniques to MITRE ATT&CK framework for educational context.
Provides technique descriptions, detection methods, and mitigation strategies.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique information."""
    technique_id: str
    name: str
    description: str
    tactic: str
    platform: List[str]
    detection_methods: List[str]
    mitigation_strategies: List[str]
    data_sources: List[str]


class MitreAttackMapper:
    """Maps attack scenarios to MITRE ATT&CK framework."""
    
    def __init__(self):
        self.techniques = self._initialize_techniques()
    
    def _initialize_techniques(self) -> Dict[str, MitreTechnique]:
        """Initialize MITRE ATT&CK technique mappings."""
        return {
            "T1611": MitreTechnique(
                technique_id="T1611",
                name="Escape to Host",
                description="Adversaries may break out of a container to gain access to the host system.",
                tactic="Privilege Escalation",
                platform=["Containers"],
                detection_methods=[
                    "Monitor for unexpected processes accessing host resources",
                    "Detect container runtime security violations",
                    "Track file system access outside container boundaries"
                ],
                mitigation_strategies=[
                    "Use non-privileged containers",
                    "Implement proper security contexts",
                    "Apply runtime security policies",
                    "Minimize host mounts"
                ],
                data_sources=["Process monitoring", "File monitoring", "Container logs"]
            ),
            
            "T1613": MitreTechnique(
                technique_id="T1613",
                name="Container and Resource Discovery",
                description="Adversaries may attempt to discover containers and other resources.",
                tactic="Discovery",
                platform=["Containers"],
                detection_methods=[
                    "Monitor API calls for resource enumeration",
                    "Track unusual kubectl/docker commands",
                    "Detect mass resource queries"
                ],
                mitigation_strategies=[
                    "Implement least-privilege access",
                    "Use network segmentation",
                    "Apply RBAC policies",
                    "Monitor resource access"
                ],
                data_sources=["API audit logs", "Command history", "Network traffic"]
            ),
            
            "T1068": MitreTechnique(
                technique_id="T1068",
                name="Exploitation for Privilege Escalation",
                description="Adversaries may exploit software vulnerabilities to escalate privileges.",
                tactic="Privilege Escalation",
                platform=["Linux", "Windows", "macOS", "Containers"],
                detection_methods=[
                    "Monitor for privilege escalation attempts",
                    "Track changes in user permissions",
                    "Detect exploitation of known vulnerabilities"
                ],
                mitigation_strategies=[
                    "Regular security updates",
                    "Vulnerability management",
                    "Least privilege principles",
                    "Application sandboxing"
                ],
                data_sources=["Authentication logs", "Process monitoring", "System calls"]
            ),
            
            "T1078": MitreTechnique(
                technique_id="T1078",
                name="Valid Accounts",
                description="Adversaries may obtain valid accounts to maintain access and avoid detection.",
                tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                platform=["Linux", "Windows", "macOS", "Azure", "AWS", "GCP"],
                detection_methods=[
                    "Monitor for unusual login patterns",
                    "Track account usage anomalies",
                    "Detect concurrent sessions from different locations"
                ],
                mitigation_strategies=[
                    "Multi-factor authentication",
                    "Account access reviews",
                    "Privileged account management",
                    "User behavior analytics"
                ],
                data_sources=["Authentication logs", "Account usage", "Login events"]
            ),
            
            "T1087": MitreTechnique(
                technique_id="T1087",
                name="Account Discovery",
                description="Adversaries may attempt to get a listing of valid accounts.",
                tactic="Discovery",
                platform=["Linux", "Windows", "macOS", "Azure", "AWS", "GCP"],
                detection_methods=[
                    "Monitor for enumeration of user accounts",
                    "Track unusual directory service queries",
                    "Detect mass account lookups"
                ],
                mitigation_strategies=[
                    "Limit account enumeration capabilities",
                    "Monitor directory service access",
                    "Implement access logging",
                    "Use least privilege principles"
                ],
                data_sources=["Authentication logs", "API logs", "Directory service logs"]
            ),
            
            "T1021": MitreTechnique(
                technique_id="T1021",
                name="Remote Services",
                description="Adversaries may use valid accounts to log into remote services.",
                tactic="Lateral Movement",
                platform=["Linux", "Windows", "macOS"],
                detection_methods=[
                    "Monitor for unusual remote service usage",
                    "Track lateral movement patterns",
                    "Detect unauthorized service access"
                ],
                mitigation_strategies=[
                    "Network segmentation",
                    "Service access controls",
                    "Multi-factor authentication",
                    "Session monitoring"
                ],
                data_sources=["Network traffic", "Authentication logs", "Service logs"]
            ),
            
            "T1552": MitreTechnique(
                technique_id="T1552",
                name="Unsecured Credentials",
                description="Adversaries may search compromised systems for credentials.",
                tactic="Credential Access",
                platform=["Linux", "Windows", "macOS", "Containers"],
                detection_methods=[
                    "Monitor file access to credential stores",
                    "Track unusual process memory access",
                    "Detect credential dumping tools"
                ],
                mitigation_strategies=[
                    "Encrypt credentials at rest",
                    "Use credential management systems",
                    "Implement least privilege",
                    "Regular credential rotation"
                ],
                data_sources=["File monitoring", "Process monitoring", "Memory analysis"]
            ),
            
            "T1053": MitreTechnique(
                technique_id="T1053",
                name="Scheduled Task/Job",
                description="Adversaries may abuse task scheduling functionality for persistence.",
                tactic="Execution, Persistence, Privilege Escalation",
                platform=["Linux", "Windows", "macOS"],
                detection_methods=[
                    "Monitor for unusual scheduled task creation",
                    "Track modifications to system schedulers",
                    "Detect persistence mechanisms"
                ],
                mitigation_strategies=[
                    "Limit scheduler access",
                    "Monitor scheduled tasks",
                    "Apply least privilege",
                    "Regular system auditing"
                ],
                data_sources=["Process monitoring", "File monitoring", "Scheduled task logs"]
            ),
            
            "T1195": MitreTechnique(
                technique_id="T1195",
                name="Supply Chain Compromise",
                description="Adversaries may manipulate products or delivery mechanisms.",
                tactic="Initial Access",
                platform=["Linux", "Windows", "macOS", "Containers"],
                detection_methods=[
                    "Monitor for unauthorized software modifications",
                    "Verify software integrity",
                    "Track dependency changes"
                ],
                mitigation_strategies=[
                    "Software supply chain security",
                    "Code signing verification",
                    "Dependency scanning",
                    "Secure build processes"
                ],
                data_sources=["Binary analysis", "Network traffic", "File integrity"]
            ),
            
            "T1195.002": MitreTechnique(
                technique_id="T1195.002",
                name="Compromise Software Supply Chain",
                description="Adversaries may manipulate application software dependencies.",
                tactic="Initial Access",
                platform=["Linux", "Windows", "macOS", "Containers"],
                detection_methods=[
                    "Dependency vulnerability scanning",
                    "Package integrity verification",
                    "Build process monitoring"
                ],
                mitigation_strategies=[
                    "Use trusted package repositories",
                    "Implement SBOM generation",
                    "Regular dependency auditing",
                    "Secure package management"
                ],
                data_sources=["Package manager logs", "Build logs", "Dependency graphs"]
            ),
            
            "T1554": MitreTechnique(
                technique_id="T1554",
                name="Compromise Client Software Binary",
                description="Adversaries may modify client software binaries for persistence.",
                tactic="Persistence",
                platform=["Linux", "Windows", "macOS"],
                detection_methods=[
                    "File integrity monitoring",
                    "Binary signature verification",
                    "Unusual process behavior detection"
                ],
                mitigation_strategies=[
                    "Code signing enforcement",
                    "Application whitelisting",
                    "Regular integrity checks",
                    "Secure update mechanisms"
                ],
                data_sources=["File monitoring", "Process monitoring", "Digital signatures"]
            )
        }
    
    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get MITRE technique by ID."""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MitreTechnique]:
        """Get techniques filtered by tactic."""
        return [
            tech for tech in self.techniques.values() 
            if tactic.lower() in tech.tactic.lower()
        ]
    
    def get_techniques_by_platform(self, platform: str) -> List[MitreTechnique]:
        """Get techniques filtered by platform."""
        return [
            tech for tech in self.techniques.values()
            if any(platform.lower() in p.lower() for p in tech.platform)
        ]
    
    def get_detection_methods(self, technique_ids: List[str]) -> Set[str]:
        """Get aggregated detection methods for given techniques."""
        methods = set()
        for technique_id in technique_ids:
            technique = self.get_technique(technique_id)
            if technique:
                methods.update(technique.detection_methods)
        return methods
    
    def get_mitigation_strategies(self, technique_ids: List[str]) -> Set[str]:
        """Get aggregated mitigation strategies for given techniques."""
        strategies = set()
        for technique_id in technique_ids:
            technique = self.get_technique(technique_id)
            if technique:
                strategies.update(technique.mitigation_strategies)
        return strategies
    
    def generate_coverage_report(self, playbook_techniques: List[str]) -> Dict:
        """Generate MITRE ATT&CK coverage report for playbook techniques."""
        tactics_covered = set()
        platforms_covered = set()
        total_techniques = len(self.techniques)
        covered_techniques = len(playbook_techniques)
        
        for technique_id in playbook_techniques:
            technique = self.get_technique(technique_id)
            if technique:
                tactics_covered.update(technique.tactic.split(", "))
                platforms_covered.update(technique.platform)
        
        return {
            "coverage_percentage": (covered_techniques / total_techniques) * 100,
            "techniques_covered": covered_techniques,
            "total_techniques": total_techniques,
            "tactics_covered": sorted(list(tactics_covered)),
            "platforms_covered": sorted(list(platforms_covered)),
            "techniques_by_tactic": {
                tactic: [
                    t.technique_id for t in self.get_techniques_by_tactic(tactic)
                    if t.technique_id in playbook_techniques
                ]
                for tactic in tactics_covered
            }
        }
    
    def export_technique_matrix(self, format: str = "json") -> str:
        """Export technique matrix in specified format."""
        if format == "json":
            import json
            return json.dumps(
                {tid: tech.__dict__ for tid, tech in self.techniques.items()},
                indent=2,
                default=str
            )
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                "Technique ID", "Name", "Tactic", "Platform", 
                "Detection Methods", "Mitigation Strategies"
            ])
            
            # Data rows
            for tech in self.techniques.values():
                writer.writerow([
                    tech.technique_id,
                    tech.name,
                    tech.tactic,
                    "; ".join(tech.platform),
                    "; ".join(tech.detection_methods),
                    "; ".join(tech.mitigation_strategies)
                ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_educational_context(self, technique_id: str) -> Dict[str, str]:
        """Get educational context for a MITRE technique."""
        technique = self.get_technique(technique_id)
        if not technique:
            return {}
        
        return {
            "technique_overview": f"{technique.name} ({technique.technique_id})",
            "description": technique.description,
            "learning_focus": f"Understanding {technique.tactic.lower()} tactics",
            "key_concepts": [
                f"How {technique.name.lower()} works in practice",
                "Detection strategies and indicators",
                "Effective mitigation approaches",
                "Real-world attack scenarios"
            ],
            "hands_on_objectives": [
                f"Simulate {technique.name.lower()} attack",
                "Implement detection mechanisms", 
                "Apply mitigation strategies",
                "Analyze attack indicators"
            ]
        }
