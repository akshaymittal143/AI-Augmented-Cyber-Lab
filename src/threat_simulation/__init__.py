"""
Threat Simulation Engine Component

Realistic attack scenario simulation aligned with MITRE ATT&CK framework.
Provides consequence-driven learning through container escapes, privilege escalation,
and Kubernetes RBAC bypass techniques.
"""

from .engine import ThreatSimulationEngine
from .playbooks import AttackPlaybook, PlaybookLibrary
from .scenarios import ContainerEscapeScenario, RBACBypassScenario
from .mitre_mapping import MitreAttackMapper

__all__ = [
    "ThreatSimulationEngine", 
    "AttackPlaybook", 
    "PlaybookLibrary",
    "ContainerEscapeScenario",
    "RBACBypassScenario", 
    "MitreAttackMapper"
]
