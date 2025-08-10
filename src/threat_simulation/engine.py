"""
Threat Simulation Engine

Core engine for orchestrating realistic attack scenarios in isolated environments.
Integrates with MITRE ATT&CK framework and provides consequence-driven learning.
"""

import asyncio
import logging
import json
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import kubernetes
from kubernetes import client, config

from .playbooks import AttackPlaybook, PlaybookLibrary
from .mitre_mapping import MitreAttackMapper


class SimulationStatus(Enum):
    """Status of threat simulation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


class ThreatCategory(Enum):
    """Categories of threats that can be simulated."""
    CONTAINER_ESCAPE = "container_escape"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"


@dataclass
class SimulationResult:
    """Result of a threat simulation."""
    simulation_id: str
    playbook_name: str
    status: SimulationStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    success_rate: float = 0.0
    detected_by_student: bool = False
    mitre_techniques: List[str] = field(default_factory=list)
    artifacts_created: List[str] = field(default_factory=list)
    logs_generated: List[Dict] = field(default_factory=list)
    educational_insights: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class SimulationEnvironment:
    """Isolated environment for threat simulation."""
    namespace: str
    cluster_context: str
    resource_limits: Dict[str, str]
    network_policies: List[str]
    monitoring_enabled: bool = True
    cleanup_policy: str = "auto"  # auto, manual, preserve


class ThreatSimulationEngine:
    """
    Engine for orchestrating realistic cybersecurity attack simulations.
    
    Features:
    - MITRE ATT&CK framework alignment
    - Container escape scenarios
    - Kubernetes RBAC bypass techniques
    - Realistic attack progression with consequences
    - Educational insight generation
    """
    
    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        default_namespace: str = "threat-simulation",
        enable_monitoring: bool = True
    ):
        self.default_namespace = default_namespace
        self.enable_monitoring = enable_monitoring
        
        # Initialize Kubernetes client
        self._init_kubernetes_client(kubeconfig_path)
        
        # Load attack playbooks
        self.playbook_library = PlaybookLibrary()
        self.mitre_mapper = MitreAttackMapper()
        
        # Active simulations tracking
        self.active_simulations: Dict[str, SimulationResult] = {}
        self.simulation_history: List[SimulationResult] = []
        
        self.logger = logging.getLogger(__name__)
    
    def _init_kubernetes_client(self, kubeconfig_path: Optional[str]):
        """Initialize Kubernetes client configuration."""
        try:
            if kubeconfig_path:
                config.load_kube_config(config_file=kubeconfig_path)
            else:
                config.load_incluster_config()
            
            self.k8s_core = client.CoreV1Api()
            self.k8s_apps = client.AppsV1Api()
            self.k8s_rbac = client.RbacAuthorizationV1Api()
            self.k8s_network = client.NetworkingV1Api()
            
            self.logger.info("Kubernetes client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes client: {str(e)}")
            raise
    
    async def start_simulation(
        self,
        playbook_name: str,
        target_environment: SimulationEnvironment,
        student_context: Optional[Dict] = None
    ) -> str:
        """
        Start a new threat simulation.
        
        Args:
            playbook_name: Name of the attack playbook to execute
            target_environment: Isolated environment for simulation
            student_context: Additional context about the student
            
        Returns:
            Simulation ID for tracking
        """
        try:
            # Load playbook
            playbook = self.playbook_library.get_playbook(playbook_name)
            if not playbook:
                raise ValueError(f"Playbook not found: {playbook_name}")
            
            # Generate unique simulation ID
            simulation_id = f"sim_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{playbook_name}"
            
            # Prepare simulation environment
            await self._prepare_environment(target_environment)
            
            # Initialize simulation result
            simulation_result = SimulationResult(
                simulation_id=simulation_id,
                playbook_name=playbook_name,
                status=SimulationStatus.RUNNING,
                start_time=datetime.utcnow(),
                mitre_techniques=playbook.mitre_techniques
            )
            
            self.active_simulations[simulation_id] = simulation_result
            
            # Start simulation in background
            asyncio.create_task(
                self._execute_simulation(playbook, target_environment, simulation_result)
            )
            
            self.logger.info(f"Started simulation {simulation_id} with playbook {playbook_name}")
            return simulation_id
            
        except Exception as e:
            self.logger.error(f"Failed to start simulation: {str(e)}")
            raise
    
    async def _execute_simulation(
        self,
        playbook: AttackPlaybook,
        environment: SimulationEnvironment,
        result: SimulationResult
    ):
        """Execute the attack simulation steps."""
        try:
            success_count = 0
            total_steps = len(playbook.steps)
            
            for i, step in enumerate(playbook.steps):
                self.logger.info(f"Executing step {i+1}/{total_steps}: {step.name}")
                
                # Execute step
                step_success = await self._execute_step(step, environment, result)
                
                if step_success:
                    success_count += 1
                    result.logs_generated.append({
                        "step": i + 1,
                        "name": step.name,
                        "status": "success",
                        "timestamp": datetime.utcnow().isoformat(),
                        "technique": step.mitre_technique,
                        "artifacts": step.artifacts_created
                    })
                else:
                    result.logs_generated.append({
                        "step": i + 1,
                        "name": step.name,
                        "status": "failed",
                        "timestamp": datetime.utcnow().isoformat(),
                        "error": "Step execution failed"
                    })
                
                # Add delay between steps for realism
                await asyncio.sleep(step.delay_seconds)
            
            # Calculate success rate
            result.success_rate = success_count / total_steps if total_steps > 0 else 0.0
            result.status = SimulationStatus.COMPLETED
            result.end_time = datetime.utcnow()
            
            # Generate educational insights
            result.educational_insights = self._generate_educational_insights(result, playbook)
            result.remediation_steps = self._generate_remediation_steps(result, playbook)
            
            # Move to history
            self.simulation_history.append(result)
            if result.simulation_id in self.active_simulations:
                del self.active_simulations[result.simulation_id]
            
            self.logger.info(f"Simulation {result.simulation_id} completed with {result.success_rate:.2%} success rate")
            
        except Exception as e:
            result.status = SimulationStatus.FAILED
            result.end_time = datetime.utcnow()
            self.logger.error(f"Simulation {result.simulation_id} failed: {str(e)}")
    
    async def _execute_step(
        self,
        step,  # AttackStep from playbooks
        environment: SimulationEnvironment,
        result: SimulationResult
    ) -> bool:
        """Execute a single attack step."""
        try:
            if step.step_type == "container_escape":
                return await self._execute_container_escape(step, environment)
            elif step.step_type == "privilege_escalation":
                return await self._execute_privilege_escalation(step, environment)
            elif step.step_type == "lateral_movement":
                return await self._execute_lateral_movement(step, environment)
            elif step.step_type == "data_access":
                return await self._execute_data_access(step, environment)
            elif step.step_type == "persistence":
                return await self._execute_persistence(step, environment)
            else:
                self.logger.warning(f"Unknown step type: {step.step_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Step execution failed: {str(e)}")
            return False
    
    async def _execute_container_escape(self, step, environment: SimulationEnvironment) -> bool:
        """Execute container escape scenario."""
        try:
            # Deploy vulnerable container
            vulnerable_pod_manifest = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": f"vulnerable-pod-{step.name.lower().replace(' ', '-')}",
                    "namespace": environment.namespace,
                    "labels": {"simulation": "container-escape"}
                },
                "spec": {
                    "containers": [{
                        "name": "vulnerable-container",
                        "image": "ubuntu:20.04",
                        "command": ["sleep", "3600"],
                        "securityContext": {
                            "privileged": True,  # Intentionally vulnerable
                            "runAsUser": 0
                        },
                        "volumeMounts": [{
                            "name": "host-root",
                            "mountPath": "/host",
                            "readOnly": False
                        }]
                    }],
                    "volumes": [{
                        "name": "host-root",
                        "hostPath": {"path": "/"}
                    }],
                    "restartPolicy": "Never"
                }
            }
            
            # Create the vulnerable pod
            self.k8s_core.create_namespaced_pod(
                namespace=environment.namespace,
                body=vulnerable_pod_manifest
            )
            
            # Wait for pod to be ready
            await asyncio.sleep(5)
            
            # Simulate escape attempt
            escape_command = [
                "kubectl", "exec", "-n", environment.namespace,
                f"vulnerable-pod-{step.name.lower().replace(' ', '-')}",
                "--", "chroot", "/host", "sh", "-c",
                "echo 'Container escaped to host!' > /tmp/escape_proof.txt"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *escape_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Check if escape was successful
            success = process.returncode == 0
            
            if success:
                step.artifacts_created.append("/tmp/escape_proof.txt")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Container escape execution failed: {str(e)}")
            return False
    
    async def _execute_privilege_escalation(self, step, environment: SimulationEnvironment) -> bool:
        """Execute privilege escalation scenario."""
        try:
            # Create service account with minimal permissions
            service_account = {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": f"test-sa-{step.name.lower().replace(' ', '-')}",
                    "namespace": environment.namespace
                }
            }
            
            self.k8s_core.create_namespaced_service_account(
                namespace=environment.namespace,
                body=service_account
            )
            
            # Create overprivileged role (intentionally vulnerable)
            role = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": f"overprivileged-role-{step.name.lower().replace(' ', '-')}",
                    "namespace": environment.namespace
                },
                "rules": [{
                    "apiGroups": ["*"],
                    "resources": ["*"],
                    "verbs": ["*"]
                }]
            }
            
            self.k8s_rbac.create_namespaced_role(
                namespace=environment.namespace,
                body=role
            )
            
            # Simulate escalation attempt
            await asyncio.sleep(2)
            return True
            
        except Exception as e:
            self.logger.error(f"Privilege escalation execution failed: {str(e)}")
            return False
    
    async def _execute_lateral_movement(self, step, environment: SimulationEnvironment) -> bool:
        """Execute lateral movement scenario."""
        # Simulate network scanning and service discovery
        await asyncio.sleep(1)
        return True
    
    async def _execute_data_access(self, step, environment: SimulationEnvironment) -> bool:
        """Execute data access scenario."""
        # Simulate unauthorized data access
        await asyncio.sleep(1)
        return True
    
    async def _execute_persistence(self, step, environment: SimulationEnvironment) -> bool:
        """Execute persistence scenario."""
        # Simulate establishing persistence mechanisms
        await asyncio.sleep(1)
        return True
    
    async def _prepare_environment(self, environment: SimulationEnvironment):
        """Prepare isolated environment for simulation."""
        try:
            # Create namespace if it doesn't exist
            try:
                self.k8s_core.read_namespace(environment.namespace)
                self.logger.info(f"Using existing namespace: {environment.namespace}")
            except client.ApiException as e:
                if e.status == 404:
                    # Create namespace
                    namespace_manifest = {
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "metadata": {
                            "name": environment.namespace,
                            "labels": {
                                "simulation": "true",
                                "created-by": "threat-simulation-engine"
                            }
                        }
                    }
                    
                    self.k8s_core.create_namespace(body=namespace_manifest)
                    self.logger.info(f"Created namespace: {environment.namespace}")
                else:
                    raise
            
            # Apply resource quotas
            if environment.resource_limits:
                await self._apply_resource_limits(environment)
            
            # Apply network policies
            if environment.network_policies:
                await self._apply_network_policies(environment)
            
        except Exception as e:
            self.logger.error(f"Environment preparation failed: {str(e)}")
            raise
    
    async def _apply_resource_limits(self, environment: SimulationEnvironment):
        """Apply resource quotas to simulation environment."""
        quota_manifest = {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {
                "name": "simulation-quota",
                "namespace": environment.namespace
            },
            "spec": {
                "hard": environment.resource_limits
            }
        }
        
        try:
            self.k8s_core.create_namespaced_resource_quota(
                namespace=environment.namespace,
                body=quota_manifest
            )
        except client.ApiException as e:
            if e.status != 409:  # Ignore if already exists
                raise
    
    async def _apply_network_policies(self, environment: SimulationEnvironment):
        """Apply network policies to simulation environment."""
        # Default deny all policy
        deny_all_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-all",
                "namespace": environment.namespace
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"]
            }
        }
        
        try:
            self.k8s_network.create_namespaced_network_policy(
                namespace=environment.namespace,
                body=deny_all_policy
            )
        except client.ApiException as e:
            if e.status != 409:  # Ignore if already exists
                raise
    
    def _generate_educational_insights(self, result: SimulationResult, playbook: AttackPlaybook) -> List[str]:
        """Generate educational insights from simulation results."""
        insights = []
        
        # Success rate insights
        if result.success_rate > 0.8:
            insights.append(f"High attack success rate ({result.success_rate:.1%}) indicates significant vulnerabilities")
        elif result.success_rate > 0.5:
            insights.append(f"Moderate attack success rate ({result.success_rate:.1%}) shows some defensive gaps")
        else:
            insights.append(f"Low attack success rate ({result.success_rate:.1%}) suggests good defensive posture")
        
        # MITRE technique insights
        techniques_used = result.mitre_techniques
        if "T1611" in techniques_used:  # Container and Resource Discovery
            insights.append("Attacker successfully discovered container environment - consider limiting service discovery")
        
        if "T1068" in techniques_used:  # Privilege Escalation
            insights.append("Privilege escalation occurred - review container security contexts and RBAC policies")
        
        # Add playbook-specific insights
        insights.extend(playbook.educational_notes)
        
        return insights
    
    def _generate_remediation_steps(self, result: SimulationResult, playbook: AttackPlaybook) -> List[str]:
        """Generate specific remediation steps based on simulation results."""
        remediation = []
        
        # Generic remediations based on successful attack steps
        successful_steps = [log for log in result.logs_generated if log.get('status') == 'success']
        
        for step_log in successful_steps:
            technique = step_log.get('technique', '')
            
            if technique == "T1611":  # Container Discovery
                remediation.append("Implement network policies to limit service discovery")
                remediation.append("Use non-root containers and read-only file systems")
            
            elif technique == "T1068":  # Privilege Escalation
                remediation.append("Remove privileged security contexts from containers")
                remediation.append("Implement least-privilege RBAC policies")
                remediation.append("Enable Pod Security Standards")
            
            elif technique == "T1021":  # Remote Services
                remediation.append("Restrict network access between pods")
                remediation.append("Implement service mesh with mTLS")
        
        # Add playbook-specific remediations
        remediation.extend(playbook.remediation_steps)
        
        return list(set(remediation))  # Remove duplicates
    
    def get_simulation_status(self, simulation_id: str) -> Optional[SimulationResult]:
        """Get current status of a simulation."""
        return self.active_simulations.get(simulation_id)
    
    def get_simulation_history(self, limit: int = 50) -> List[SimulationResult]:
        """Get history of completed simulations."""
        return self.simulation_history[-limit:]
    
    async def terminate_simulation(self, simulation_id: str):
        """Terminate a running simulation."""
        if simulation_id in self.active_simulations:
            result = self.active_simulations[simulation_id]
            result.status = SimulationStatus.TERMINATED
            result.end_time = datetime.utcnow()
            
            # Move to history
            self.simulation_history.append(result)
            del self.active_simulations[simulation_id]
            
            self.logger.info(f"Terminated simulation {simulation_id}")
    
    async def cleanup_environment(self, environment: SimulationEnvironment):
        """Clean up simulation environment resources."""
        try:
            if environment.cleanup_policy == "auto":
                # Delete all resources in the namespace
                self.k8s_core.delete_namespace(name=environment.namespace)
                self.logger.info(f"Cleaned up namespace: {environment.namespace}")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
    
    def get_available_playbooks(self) -> List[str]:
        """Get list of available attack playbooks."""
        return self.playbook_library.list_playbooks()
    
    def get_mitre_techniques_covered(self) -> List[str]:
        """Get list of MITRE ATT&CK techniques covered by available playbooks."""
        techniques = set()
        for playbook_name in self.playbook_library.list_playbooks():
            playbook = self.playbook_library.get_playbook(playbook_name)
            if playbook:
                techniques.update(playbook.mitre_techniques)
        return sorted(list(techniques))
