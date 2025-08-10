"""
RL Training Environment

Gymnasium-compatible environment wrapper for training the RL hint agent.
Simulates the cyber lab learning environment for reinforcement learning.
"""

import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .agent import StudentState, StudentLevel, HintType, EnvironmentState
from ..llm_analyzer.analyzer import SecurityFinding


@dataclass
class SimulatedStudent:
    """Simulated student for RL training."""
    student_id: str
    level: StudentLevel
    learning_rate: float = 0.1
    hint_responsiveness: float = 0.8
    frustration_threshold: float = 0.7
    current_frustration: float = 0.0
    skill_areas: Dict[str, float] = None  # Skill levels in different areas


class CyberLabEnvironment(gym.Env):
    """
    Gymnasium environment for training the RL hint agent.
    
    Simulates student interactions in the cyber lab environment
    and provides rewards based on learning outcomes.
    """
    
    def __init__(
        self,
        max_episode_steps: int = 100,
        num_vulnerability_types: int = 7,
        hint_budget: int = 10
    ):
        super().__init__()
        
        self.max_episode_steps = max_episode_steps
        self.num_vulnerability_types = num_vulnerability_types
        self.hint_budget = hint_budget
        
        # Define observation space
        # [student_features(9) + context_features(5) + vulnerability_indicators(7) + time_features(2)]
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf,
            shape=(23,), dtype=np.float32
        )
        
        # Define action space (hint types)
        self.action_space = spaces.Discrete(len(HintType))
        
        # Environment state
        self.current_student: Optional[SimulatedStudent] = None
        self.current_episode_step = 0
        self.hints_used = 0
        self.current_task_findings: List[SecurityFinding] = []
        self.task_completed = False
        self.last_hint_effectiveness = 0.0
        
        # Simulation parameters
        self.task_difficulty_levels = ['easy', 'medium', 'hard']
        self.current_task_difficulty = 'medium'
        
    def reset(self, seed: Optional[int] = None, options: Optional[dict] = None) -> Tuple[np.ndarray, dict]:
        """Reset environment for new episode."""
        super().reset(seed=seed)
        
        # Create new simulated student
        self.current_student = self._create_random_student()
        
        # Reset episode state
        self.current_episode_step = 0
        self.hints_used = 0
        self.task_completed = False
        self.last_hint_effectiveness = 0.0
        
        # Generate new task
        self.current_task_findings = self._generate_task_findings()
        self.current_task_difficulty = np.random.choice(self.task_difficulty_levels)
        
        observation = self._get_observation()
        info = self._get_info()
        
        return observation, info
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, dict]:
        """Execute one step in the environment."""
        self.current_episode_step += 1
        self.hints_used += 1
        
        # Convert action to hint type
        hint_type = list(HintType)[action]
        
        # Simulate student response to hint
        hint_effectiveness = self._simulate_hint_response(hint_type)
        self.last_hint_effectiveness = hint_effectiveness
        
        # Update student state based on hint
        self._update_student_state(hint_type, hint_effectiveness)
        
        # Calculate reward
        reward = self._calculate_reward(hint_type, hint_effectiveness)
        
        # Check if episode is done
        terminated = self.task_completed or self.hints_used >= self.hint_budget
        truncated = self.current_episode_step >= self.max_episode_steps
        
        observation = self._get_observation()
        info = self._get_info()
        
        return observation, reward, terminated, truncated, info
    
    def _create_random_student(self) -> SimulatedStudent:
        """Create a random simulated student."""
        levels = list(StudentLevel)
        level = np.random.choice(levels)
        
        # Generate skill areas based on level
        base_skill = {
            StudentLevel.NOVICE: 0.2,
            StudentLevel.INTERMEDIATE: 0.5,
            StudentLevel.ADVANCED: 0.8,
            StudentLevel.OPTIMAL: 0.95
        }[level]
        
        skill_areas = {}
        for vuln_type in ['privilege_escalation', 'secrets_management', 'container_security',
                         'network_security', 'access_control', 'supply_chain', 'misconfiguration']:
            # Add some variance around base skill
            skill_areas[vuln_type] = np.clip(
                np.random.normal(base_skill, 0.1), 0.0, 1.0
            )
        
        return SimulatedStudent(
            student_id=f"sim_student_{np.random.randint(1000, 9999)}",
            level=level,
            learning_rate=np.random.uniform(0.05, 0.2),
            hint_responsiveness=np.random.uniform(0.6, 0.9),
            frustration_threshold=np.random.uniform(0.5, 0.8),
            current_frustration=0.0,
            skill_areas=skill_areas
        )
    
    def _generate_task_findings(self) -> List[SecurityFinding]:
        """Generate simulated security findings for the current task."""
        num_findings = np.random.randint(1, 5)  # 1-4 findings per task
        findings = []
        
        vulnerability_types = ['privilege_escalation', 'secrets_management', 'container_security',
                              'network_security', 'access_control', 'supply_chain', 'misconfiguration']
        
        for i in range(num_findings):
            vuln_type = np.random.choice(vulnerability_types)
            severity = np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
                                      p=[0.2, 0.3, 0.3, 0.2])
            
            finding = SecurityFinding(
                finding_id=f"TASK_{i+1}",
                severity=severity,
                category=vuln_type,
                title=f"Simulated {vuln_type} vulnerability",
                description=f"This is a simulated {severity.lower()} severity {vuln_type} issue",
                line_number=np.random.randint(1, 100),
                remediation=f"Fix the {vuln_type} issue",
                confidence=np.random.uniform(0.7, 1.0)
            )
            findings.append(finding)
        
        return findings
    
    def _simulate_hint_response(self, hint_type: HintType) -> float:
        """Simulate how effectively the student responds to a hint."""
        if not self.current_student:
            return 0.0
        
        # Base effectiveness depends on hint type appropriateness
        base_effectiveness = self._get_hint_type_effectiveness(hint_type)
        
        # Modify based on student characteristics
        student_modifier = self.current_student.hint_responsiveness
        
        # Reduce effectiveness if student is frustrated
        frustration_penalty = self.current_student.current_frustration * 0.3
        
        # Random variation
        noise = np.random.normal(0, 0.1)
        
        effectiveness = base_effectiveness * student_modifier - frustration_penalty + noise
        return np.clip(effectiveness, 0.0, 1.0)
    
    def _get_hint_type_effectiveness(self, hint_type: HintType) -> float:
        """Get base effectiveness of hint type for current context."""
        if not self.current_student:
            return 0.5
        
        # Effectiveness varies by student level and hint type
        effectiveness_matrix = {
            StudentLevel.NOVICE: {
                HintType.CONCEPTUAL: 0.8,
                HintType.TACTICAL: 0.4,
                HintType.DIAGNOSTIC: 0.6,
                HintType.REMEDIATION: 0.9,
                HintType.ENCOURAGEMENT: 0.7
            },
            StudentLevel.INTERMEDIATE: {
                HintType.CONCEPTUAL: 0.6,
                HintType.TACTICAL: 0.8,
                HintType.DIAGNOSTIC: 0.7,
                HintType.REMEDIATION: 0.5,
                HintType.ENCOURAGEMENT: 0.4
            },
            StudentLevel.ADVANCED: {
                HintType.CONCEPTUAL: 0.4,
                HintType.TACTICAL: 0.7,
                HintType.DIAGNOSTIC: 0.9,
                HintType.REMEDIATION: 0.3,
                HintType.ENCOURAGEMENT: 0.2
            },
            StudentLevel.OPTIMAL: {
                HintType.CONCEPTUAL: 0.2,
                HintType.TACTICAL: 0.3,
                HintType.DIAGNOSTIC: 0.4,
                HintType.REMEDIATION: 0.1,
                HintType.ENCOURAGEMENT: 0.1
            }
        }
        
        return effectiveness_matrix[self.current_student.level][hint_type]
    
    def _update_student_state(self, hint_type: HintType, effectiveness: float):
        """Update student state based on hint interaction."""
        if not self.current_student:
            return
        
        # Update frustration
        if effectiveness < 0.3:
            self.current_student.current_frustration += 0.1
        elif effectiveness > 0.7:
            self.current_student.current_frustration = max(0, 
                self.current_student.current_frustration - 0.05)
        
        # Update skill areas based on learning
        if effectiveness > 0.5:
            for finding in self.current_task_findings:
                category = finding.category
                if category in self.current_student.skill_areas:
                    learning_gain = effectiveness * self.current_student.learning_rate
                    current_skill = self.current_student.skill_areas[category]
                    self.current_student.skill_areas[category] = min(1.0, 
                        current_skill + learning_gain)
        
        # Check if task is completed
        self._check_task_completion()
    
    def _check_task_completion(self) -> bool:
        """Check if the current task is completed based on student progress."""
        if not self.current_student:
            return False
        
        # Task completion based on student skill and hint effectiveness
        completion_threshold = 0.8
        
        # Calculate average skill for current task findings
        relevant_skills = []
        for finding in self.current_task_findings:
            if finding.category in self.current_student.skill_areas:
                relevant_skills.append(self.current_student.skill_areas[finding.category])
        
        if relevant_skills:
            avg_skill = np.mean(relevant_skills)
            # Add some randomness for realism
            completion_probability = avg_skill + np.random.normal(0, 0.1)
            
            if completion_probability > completion_threshold:
                self.task_completed = True
                return True
        
        return False
    
    def _calculate_reward(self, hint_type: HintType, effectiveness: float) -> float:
        """Calculate reward for the hint action."""
        # Base reward from hint effectiveness
        effectiveness_reward = effectiveness * 5.0
        
        # Penalty for using hints (encourage efficiency)
        hint_penalty = -0.5
        
        # Bonus for task completion
        completion_bonus = 10.0 if self.task_completed else 0.0
        
        # Penalty for student frustration
        frustration_penalty = -self.current_student.current_frustration * 2.0 if self.current_student else 0.0
        
        # Bonus for appropriate hint timing
        timing_bonus = 0.0
        if self.hints_used <= 3 and effectiveness > 0.7:  # Good early hint
            timing_bonus = 2.0
        
        total_reward = (effectiveness_reward + hint_penalty + completion_bonus + 
                       frustration_penalty + timing_bonus)
        
        return np.clip(total_reward, -10.0, 15.0)
    
    def _get_observation(self) -> np.ndarray:
        """Get current observation vector."""
        if not self.current_student:
            return np.zeros(23, dtype=np.float32)
        
        # Student features (9 dimensions)
        student_features = [
            # Student level (one-hot encoded)
            1.0 if self.current_student.level == StudentLevel.NOVICE else 0.0,
            1.0 if self.current_student.level == StudentLevel.INTERMEDIATE else 0.0,
            1.0 if self.current_student.level == StudentLevel.ADVANCED else 0.0,
            1.0 if self.current_student.level == StudentLevel.OPTIMAL else 0.0,
            
            # Student characteristics
            self.current_student.learning_rate,
            self.current_student.hint_responsiveness,
            self.current_student.current_frustration,
            
            # Average skill across areas
            np.mean(list(self.current_student.skill_areas.values())),
            
            # Last hint effectiveness
            self.last_hint_effectiveness
        ]
        
        # Context features (5 dimensions)
        context_features = [
            len(self.current_task_findings) / 5.0,  # Normalized number of findings
            self.hints_used / self.hint_budget,  # Hint budget usage
            self.current_episode_step / self.max_episode_steps,  # Episode progress
            1.0 if self.task_completed else 0.0,  # Task completion status
            {'easy': 0.3, 'medium': 0.6, 'hard': 0.9}[self.current_task_difficulty]  # Difficulty
        ]
        
        # Vulnerability indicators (7 dimensions)
        vuln_indicators = []
        for vuln_type in ['privilege_escalation', 'secrets_management', 'container_security',
                         'network_security', 'access_control', 'supply_chain', 'misconfiguration']:
            has_vuln = any(f.category == vuln_type for f in self.current_task_findings)
            vuln_indicators.append(1.0 if has_vuln else 0.0)
        
        # Time features (2 dimensions)
        time_features = [
            self.current_episode_step / self.max_episode_steps,  # Episode progress
            (self.max_episode_steps - self.current_episode_step) / self.max_episode_steps  # Time remaining
        ]
        
        # Combine all features
        observation = np.array(
            student_features + context_features + vuln_indicators + time_features,
            dtype=np.float32
        )
        
        return observation
    
    def _get_info(self) -> dict:
        """Get additional info about the current state."""
        return {
            'student_level': self.current_student.level.value if self.current_student else None,
            'hints_used': self.hints_used,
            'hint_budget_remaining': self.hint_budget - self.hints_used,
            'task_completed': self.task_completed,
            'current_frustration': self.current_student.current_frustration if self.current_student else 0,
            'episode_step': self.current_episode_step,
            'task_difficulty': self.current_task_difficulty,
            'num_findings': len(self.current_task_findings),
            'last_hint_effectiveness': self.last_hint_effectiveness
        }
    
    def render(self, mode: str = 'human'):
        """Render the environment state."""
        if mode == 'human':
            print(f"Episode Step: {self.current_episode_step}/{self.max_episode_steps}")
            print(f"Hints Used: {self.hints_used}/{self.hint_budget}")
            print(f"Task Completed: {self.task_completed}")
            if self.current_student:
                print(f"Student Level: {self.current_student.level.value}")
                print(f"Student Frustration: {self.current_student.current_frustration:.2f}")
                print(f"Last Hint Effectiveness: {self.last_hint_effectiveness:.2f}")
            print("-" * 40)
