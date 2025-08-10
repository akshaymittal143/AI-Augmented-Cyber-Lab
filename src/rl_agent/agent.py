"""
RL Hint Agent

Reinforcement learning agent for adaptive hint delivery in cybersecurity education.
Uses Q-learning and multi-armed bandit approaches for personalized scaffolding.
"""

import numpy as np
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import pickle
from collections import deque, defaultdict

import gym
from gym import spaces
from stable_baselines3 import DQN, PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback

from ..llm_analyzer.analyzer import SecurityFinding


class StudentLevel(Enum):
    """Student competence levels."""
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    OPTIMAL = "optimal"


class HintType(Enum):
    """Types of hints that can be provided."""
    CONCEPTUAL = "conceptual"      # High-level security concepts
    TACTICAL = "tactical"          # Specific implementation guidance  
    DIAGNOSTIC = "diagnostic"      # Help identify the problem
    REMEDIATION = "remediation"    # Direct fix instructions
    ENCOURAGEMENT = "encouragement" # Motivational support


@dataclass
class StudentState:
    """Current state of a student in the learning environment."""
    student_id: str
    level: StudentLevel
    current_task: str
    attempts: int = 0
    hints_used: int = 0
    time_spent: float = 0.0
    last_action_time: float = 0.0
    error_patterns: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    hint_effectiveness: Dict[HintType, float] = field(default_factory=dict)
    learning_velocity: float = 0.0  # Rate of improvement


@dataclass
class HintAction:
    """Action representing a hint to be delivered."""
    hint_type: HintType
    content: str
    timing_delay: float = 0.0  # Seconds to wait before delivering
    confidence: float = 1.0
    expected_impact: float = 0.0


@dataclass
class EnvironmentState:
    """Complete state of the learning environment."""
    student_state: StudentState
    current_findings: List[SecurityFinding]
    lab_context: Dict[str, Any]
    time_remaining: float
    hint_budget: int  # Maximum hints allowed


class RLHintAgent:
    """
    Reinforcement Learning agent for adaptive hint delivery.
    
    Uses Deep Q-Network (DQN) for hint selection and multi-armed bandit
    for timing optimization. Balances learning gains against hint dependency.
    """
    
    def __init__(
        self,
        learning_rate: float = 0.001,
        epsilon: float = 0.1,
        gamma: float = 0.95,
        buffer_size: int = 10000,
        model_path: Optional[str] = None
    ):
        self.learning_rate = learning_rate
        self.epsilon = epsilon
        self.gamma = gamma
        self.buffer_size = buffer_size
        
        # Initialize Q-network for hint selection
        self.hint_model = None
        self.timing_model = None
        
        # Hint effectiveness tracking
        self.hint_history = deque(maxlen=1000)
        self.student_profiles = {}
        
        # Multi-armed bandit for timing
        self.timing_bandits = {
            level: self._initialize_timing_bandit() 
            for level in StudentLevel
        }
        
        self.logger = logging.getLogger(__name__)
        
        if model_path:
            self.load_model(model_path)
        else:
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize the RL models for hint selection and timing."""
        
        # Define observation and action spaces
        # Observation: student state + environment state (normalized)
        observation_space = spaces.Box(
            low=-np.inf, high=np.inf, 
            shape=(20,), dtype=np.float32
        )
        
        # Action space: hint type selection (5 types)
        action_space = spaces.Discrete(len(HintType))
        
        # Create custom environment for training
        from .environment import CyberLabEnvironment
        env = CyberLabEnvironment(
            observation_space=observation_space,
            action_space=action_space
        )
        
        # Initialize DQN for hint selection
        self.hint_model = DQN(
            "MlpPolicy",
            env,
            learning_rate=self.learning_rate,
            buffer_size=self.buffer_size,
            learning_starts=100,
            batch_size=32,
            tau=1.0,
            gamma=self.gamma,
            train_freq=4,
            gradient_steps=1,
            target_update_interval=1000,
            exploration_fraction=0.1,
            exploration_initial_eps=1.0,
            exploration_final_eps=self.epsilon,
            verbose=1
        )
        
        self.logger.info("Initialized RL models for hint selection")
    
    def select_hint(
        self, 
        env_state: EnvironmentState,
        available_hints: List[str]
    ) -> Optional[HintAction]:
        """
        Select the most appropriate hint for the current situation.
        
        Args:
            env_state: Current environment state
            available_hints: List of available hint contents
            
        Returns:
            Selected hint action or None if no hint recommended
        """
        try:
            # Check if hint is warranted
            if not self._should_provide_hint(env_state):
                return None
            
            # Convert environment state to observation
            observation = self._encode_observation(env_state)
            
            # Get hint type recommendation from DQN
            action, _states = self.hint_model.predict(
                observation, deterministic=False
            )
            
            hint_type = list(HintType)[action]
            
            # Select specific hint content
            hint_content = self._select_hint_content(
                hint_type, env_state, available_hints
            )
            
            # Determine timing with multi-armed bandit
            timing_delay = self._select_timing(env_state.student_state.level)
            
            # Estimate expected impact
            expected_impact = self._estimate_hint_impact(
                hint_type, env_state
            )
            
            hint_action = HintAction(
                hint_type=hint_type,
                content=hint_content,
                timing_delay=timing_delay,
                confidence=1.0 - self.epsilon,
                expected_impact=expected_impact
            )
            
            self.logger.info(f"Selected hint: {hint_type.value} with delay {timing_delay}s")
            return hint_action
            
        except Exception as e:
            self.logger.error(f"Hint selection failed: {str(e)}")
            return None
    
    def _should_provide_hint(self, env_state: EnvironmentState) -> bool:
        """Determine if a hint should be provided based on current state."""
        student = env_state.student_state
        
        # Don't provide hints if budget exhausted
        if env_state.hint_budget <= 0:
            return False
        
        # Don't provide hints too frequently
        min_interval = self._get_min_hint_interval(student.level)
        time_since_last = env_state.lab_context.get('time_since_last_hint', 0)
        
        if time_since_last < min_interval:
            return False
        
        # Provide hints based on struggle indicators
        struggle_score = self._calculate_struggle_score(env_state)
        hint_threshold = self._get_hint_threshold(student.level)
        
        return struggle_score > hint_threshold
    
    def _calculate_struggle_score(self, env_state: EnvironmentState) -> float:
        """Calculate how much the student is struggling (0.0 - 1.0)."""
        student = env_state.student_state
        
        # Factors indicating struggle
        attempt_factor = min(student.attempts / 5.0, 1.0)  # Normalize attempts
        time_factor = min(student.time_spent / 600.0, 1.0)  # 10 minutes max
        error_factor = len(student.error_patterns) / 10.0  # Up to 10 error types
        
        # Success rate factor (inverse)
        success_factor = 1.0 - student.success_rate
        
        # Weighted combination
        struggle_score = (
            0.3 * attempt_factor +
            0.2 * time_factor +
            0.3 * error_factor +
            0.2 * success_factor
        )
        
        return min(struggle_score, 1.0)
    
    def _encode_observation(self, env_state: EnvironmentState) -> np.ndarray:
        """Encode environment state as observation vector for the RL model."""
        student = env_state.student_state
        
        # Student features (normalized)
        obs = np.array([
            # Student level (one-hot encoded)
            1.0 if student.level == StudentLevel.NOVICE else 0.0,
            1.0 if student.level == StudentLevel.INTERMEDIATE else 0.0,
            1.0 if student.level == StudentLevel.ADVANCED else 0.0,
            1.0 if student.level == StudentLevel.OPTIMAL else 0.0,
            
            # Performance metrics (normalized)
            min(student.attempts / 10.0, 1.0),
            min(student.hints_used / 5.0, 1.0),
            min(student.time_spent / 1200.0, 1.0),  # 20 minutes max
            student.success_rate,
            student.learning_velocity,
            
            # Current context
            len(env_state.current_findings) / 10.0,  # Up to 10 findings
            env_state.time_remaining / 3600.0,  # Up to 1 hour
            env_state.hint_budget / 10.0,  # Up to 10 hints
            
            # Hint effectiveness (average across types)
            np.mean(list(student.hint_effectiveness.values())) if student.hint_effectiveness else 0.0,
            
            # Struggle score
            self._calculate_struggle_score(env_state),
            
            # Recent error patterns (binary indicators)
            1.0 if 'privilege_escalation' in student.error_patterns else 0.0,
            1.0 if 'secret_management' in student.error_patterns else 0.0,
            1.0 if 'network_security' in student.error_patterns else 0.0,
            1.0 if 'access_control' in student.error_patterns else 0.0,
            1.0 if 'container_security' in student.error_patterns else 0.0,
            
            # Time since last hint (normalized)
            min(env_state.lab_context.get('time_since_last_hint', 0) / 300.0, 1.0),
        ], dtype=np.float32)
        
        return obs
    
    def _select_hint_content(
        self, 
        hint_type: HintType, 
        env_state: EnvironmentState,
        available_hints: List[str]
    ) -> str:
        """Select specific hint content based on type and context."""
        
        # Filter hints by type and relevance
        relevant_hints = []
        
        for hint in available_hints:
            if self._is_hint_relevant(hint, hint_type, env_state):
                relevant_hints.append(hint)
        
        if not relevant_hints:
            return self._generate_fallback_hint(hint_type, env_state)
        
        # Select most appropriate hint based on student state
        return self._rank_hints(relevant_hints, env_state)[0]
    
    def _select_timing(self, student_level: StudentLevel) -> float:
        """Select timing delay using multi-armed bandit approach."""
        bandit = self.timing_bandits[student_level]
        
        # Epsilon-greedy selection
        if np.random.random() < self.epsilon:
            # Explore: random timing
            return np.random.uniform(0, 30)  # 0-30 seconds
        else:
            # Exploit: best known timing
            return bandit['best_timing']
    
    def update_feedback(
        self,
        hint_action: HintAction,
        env_state_before: EnvironmentState,
        env_state_after: EnvironmentState,
        student_progress: float
    ):
        """
        Update the RL model based on feedback from hint delivery.
        
        Args:
            hint_action: The hint action that was taken
            env_state_before: Environment state before hint
            env_state_after: Environment state after hint
            student_progress: Measured progress (0.0 - 1.0)
        """
        try:
            # Calculate reward based on progress and efficiency
            reward = self._calculate_reward(
                hint_action, env_state_before, env_state_after, student_progress
            )
            
            # Store experience for model training
            observation_before = self._encode_observation(env_state_before)
            observation_after = self._encode_observation(env_state_after)
            
            action = list(HintType).index(hint_action.hint_type)
            
            # Update hint effectiveness tracking
            self._update_hint_effectiveness(
                env_state_before.student_state, hint_action, student_progress
            )
            
            # Update timing bandit
            self._update_timing_bandit(
                env_state_before.student_state.level,
                hint_action.timing_delay,
                student_progress
            )
            
            # Add to training buffer (this would trigger model updates)
            self.hint_history.append({
                'observation': observation_before,
                'action': action,
                'reward': reward,
                'next_observation': observation_after,
                'done': env_state_after.time_remaining <= 0,
                'student_progress': student_progress
            })
            
            self.logger.info(f"Updated feedback: reward={reward:.3f}, progress={student_progress:.3f}")
            
        except Exception as e:
            self.logger.error(f"Feedback update failed: {str(e)}")
    
    def _calculate_reward(
        self,
        hint_action: HintAction,
        env_before: EnvironmentState,
        env_after: EnvironmentState,
        progress: float
    ) -> float:
        """Calculate reward for the hint action."""
        
        # Base reward from student progress
        progress_reward = progress * 10.0
        
        # Penalty for hint usage (encourage efficiency)
        hint_penalty = -1.0
        
        # Bonus for appropriate timing
        timing_bonus = 0.0
        if 0.5 <= progress <= 1.0:  # Good timing if progress made
            timing_bonus = 2.0
        
        # Penalty for over-hinting
        hints_used_after = env_after.student_state.hints_used
        over_hint_penalty = -max(0, hints_used_after - 5) * 0.5
        
        total_reward = progress_reward + hint_penalty + timing_bonus + over_hint_penalty
        
        return np.clip(total_reward, -10.0, 10.0)
    
    def _update_hint_effectiveness(
        self, 
        student: StudentState, 
        hint_action: HintAction, 
        progress: float
    ):
        """Update tracking of hint effectiveness for this student."""
        hint_type = hint_action.hint_type
        
        # Initialize if first time
        if hint_type not in student.hint_effectiveness:
            student.hint_effectiveness[hint_type] = 0.5
        
        # Update with exponential moving average
        alpha = 0.3  # Learning rate
        current_effectiveness = student.hint_effectiveness[hint_type]
        new_effectiveness = alpha * progress + (1 - alpha) * current_effectiveness
        
        student.hint_effectiveness[hint_type] = new_effectiveness
    
    def train(self, episodes: int = 1000):
        """Train the RL model using collected experiences."""
        if len(self.hint_history) < 100:  # Minimum experiences needed
            self.logger.warning("Insufficient training data for RL model")
            return
        
        self.logger.info(f"Training RL model on {len(self.hint_history)} experiences")
        
        # Train the DQN model
        self.hint_model.learn(total_timesteps=episodes)
        
        self.logger.info("RL model training completed")
    
    def save_model(self, path: str):
        """Save the trained RL model."""
        self.hint_model.save(path)
        
        # Save additional state
        state = {
            'timing_bandits': self.timing_bandits,
            'hint_history': list(self.hint_history),
            'student_profiles': self.student_profiles
        }
        
        with open(f"{path}_state.pkl", 'wb') as f:
            pickle.dump(state, f)
        
        self.logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """Load a trained RL model."""
        self.hint_model = DQN.load(path)
        
        # Load additional state
        try:
            with open(f"{path}_state.pkl", 'rb') as f:
                state = pickle.load(f)
                self.timing_bandits = state['timing_bandits']
                self.hint_history = deque(state['hint_history'], maxlen=1000)
                self.student_profiles = state['student_profiles']
        except FileNotFoundError:
            self.logger.warning("Additional state file not found, using defaults")
        
        self.logger.info(f"Model loaded from {path}")
    
    def _initialize_timing_bandit(self) -> Dict:
        """Initialize multi-armed bandit for timing optimization."""
        return {
            'arms': [0, 5, 10, 15, 30],  # Timing options in seconds
            'counts': [1] * 5,  # Initialize with 1 to avoid division by zero
            'values': [0.5] * 5,  # Initialize with neutral value
            'best_timing': 10.0  # Default timing
        }
    
    def _update_timing_bandit(self, level: StudentLevel, timing: float, progress: float):
        """Update timing bandit based on results."""
        bandit = self.timing_bandits[level]
        
        # Find closest arm
        closest_arm = min(range(len(bandit['arms'])), 
                         key=lambda i: abs(bandit['arms'][i] - timing))
        
        # Update arm statistics
        bandit['counts'][closest_arm] += 1
        n = bandit['counts'][closest_arm]
        value = bandit['values'][closest_arm]
        
        # Update value with incremental average
        bandit['values'][closest_arm] = value + (progress - value) / n
        
        # Update best timing
        best_arm = np.argmax(bandit['values'])
        bandit['best_timing'] = bandit['arms'][best_arm]
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get current performance metrics of the RL agent."""
        if not self.hint_history:
            return {}
        
        recent_experiences = list(self.hint_history)[-100:]  # Last 100 experiences
        
        return {
            'average_reward': np.mean([exp['reward'] for exp in recent_experiences]),
            'average_progress': np.mean([exp['student_progress'] for exp in recent_experiences]),
            'total_experiences': len(self.hint_history),
            'model_training_status': 'trained' if self.hint_model else 'untrained'
        }
    
    def _get_min_hint_interval(self, level: StudentLevel) -> float:
        """Get minimum interval between hints based on student level."""
        intervals = {
            StudentLevel.NOVICE: 15.0,      # 15 seconds
            StudentLevel.INTERMEDIATE: 30.0,  # 30 seconds  
            StudentLevel.ADVANCED: 60.0,     # 1 minute
            StudentLevel.OPTIMAL: 120.0      # 2 minutes
        }
        return intervals.get(level, 30.0)
    
    def _get_hint_threshold(self, level: StudentLevel) -> float:
        """Get struggle threshold for providing hints."""
        thresholds = {
            StudentLevel.NOVICE: 0.3,       # Provide hints early
            StudentLevel.INTERMEDIATE: 0.5,  # Moderate threshold
            StudentLevel.ADVANCED: 0.7,     # Let them struggle more
            StudentLevel.OPTIMAL: 0.9       # Minimal hints
        }
        return thresholds.get(level, 0.5)
    
    def _estimate_hint_impact(self, hint_type: HintType, env_state: EnvironmentState) -> float:
        """Estimate expected impact of a hint type in current context."""
        student = env_state.student_state
        
        # Use historical effectiveness if available
        if hint_type in student.hint_effectiveness:
            return student.hint_effectiveness[hint_type]
        
        # Default estimates based on hint type and student level
        base_impacts = {
            HintType.CONCEPTUAL: 0.4,
            HintType.TACTICAL: 0.6,
            HintType.DIAGNOSTIC: 0.5,
            HintType.REMEDIATION: 0.8,
            HintType.ENCOURAGEMENT: 0.3
        }
        
        # Adjust for student level
        level_multipliers = {
            StudentLevel.NOVICE: 1.2,
            StudentLevel.INTERMEDIATE: 1.0,
            StudentLevel.ADVANCED: 0.8,
            StudentLevel.OPTIMAL: 0.6
        }
        
        base_impact = base_impacts.get(hint_type, 0.5)
        multiplier = level_multipliers.get(student.level, 1.0)
        
        return min(base_impact * multiplier, 1.0)
    
    def _is_hint_relevant(self, hint: str, hint_type: HintType, env_state: EnvironmentState) -> bool:
        """Check if a hint is relevant to the current context."""
        # Simple keyword matching - could be enhanced with NLP
        type_keywords = {
            HintType.CONCEPTUAL: ['concept', 'principle', 'why', 'security'],
            HintType.TACTICAL: ['how', 'implement', 'configure', 'setup'],
            HintType.DIAGNOSTIC: ['check', 'look', 'examine', 'identify'],
            HintType.REMEDIATION: ['fix', 'change', 'replace', 'update'],
            HintType.ENCOURAGEMENT: ['good', 'try', 'progress', 'keep']
        }
        
        keywords = type_keywords.get(hint_type, [])
        return any(keyword.lower() in hint.lower() for keyword in keywords)
    
    def _generate_fallback_hint(self, hint_type: HintType, env_state: EnvironmentState) -> str:
        """Generate a fallback hint when no pre-written hints are available."""
        fallback_hints = {
            HintType.CONCEPTUAL: "Consider the security principles involved in this scenario.",
            HintType.TACTICAL: "Think about the specific implementation steps needed.",
            HintType.DIAGNOSTIC: "Look carefully at the configuration for potential issues.",
            HintType.REMEDIATION: "Focus on the specific changes needed to fix this issue.",
            HintType.ENCOURAGEMENT: "You're making good progress! Keep analyzing the problem."
        }
        
        return fallback_hints.get(hint_type, "Consider reviewing the security requirements.")
    
    def _rank_hints(self, hints: List[str], env_state: EnvironmentState) -> List[str]:
        """Rank hints by relevance to current context."""
        # Simple ranking based on current findings
        findings_keywords = []
        for finding in env_state.current_findings:
            findings_keywords.extend(finding.category.lower().split())
            findings_keywords.extend(finding.title.lower().split())
        
        def relevance_score(hint: str) -> float:
            hint_words = set(hint.lower().split())
            keyword_matches = len(hint_words.intersection(set(findings_keywords)))
            return keyword_matches / len(hint_words) if hint_words else 0.0
        
        return sorted(hints, key=relevance_score, reverse=True)
