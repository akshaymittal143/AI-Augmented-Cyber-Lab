#!/usr/bin/env python3
"""
RL Agent Evaluation Script

This script evaluates the Reinforcement Learning Hint Agent performance
across different learner personas as described in the paper.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any

import numpy as np
import pandas as pd
from stable_baselines3 import DQN
from stable_baselines3.common.evaluation import evaluate_policy

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

from rl_agent.environment import CyberLabEnvironment
from rl_agent.agent import RLHintAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RLEvaluator:
    """Evaluates RL agent performance across different learner personas."""
    
    def __init__(self, config_path: str):
        """Initialize evaluator with configuration."""
        self.config = self._load_config(config_path)
        self.results = {}
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load evaluation configuration."""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def evaluate_persona(self, persona: str, episodes: int = 1000) -> Dict[str, Any]:
        """Evaluate RL agent performance for a specific learner persona."""
        logger.info(f"Evaluating RL agent for {persona} persona...")
        
        # Create environment for this persona
        env = CyberLabEnvironment(
            persona_type=persona,
            max_steps=self.config.get('max_steps', 100),
            hint_cooldown=self.config.get('hint_cooldown', 30)
        )
        
        # Load trained agent
        agent = RLHintAgent.load(f"models/rl_agent_{persona}.zip")
        
        # Evaluate policy
        mean_reward, std_reward = evaluate_policy(
            agent.model, 
            env, 
            n_eval_episodes=episodes,
            deterministic=True
        )
        
        # Calculate additional metrics
        metrics = self._calculate_metrics(agent, env, episodes)
        
        results = {
            'persona': persona,
            'episodes': episodes,
            'mean_reward': float(mean_reward),
            'std_reward': float(std_reward),
            'metrics': metrics
        }
        
        logger.info(f"Completed evaluation for {persona}: {mean_reward:.3f} ± {std_reward:.3f}")
        return results
    
    def _calculate_metrics(self, agent: RLHintAgent, env: CyberLabEnvironment, episodes: int) -> Dict[str, float]:
        """Calculate detailed performance metrics."""
        rewards = []
        hint_counts = []
        success_rates = []
        
        for episode in range(episodes):
            obs = env.reset()
            episode_reward = 0
            hint_count = 0
            
            while True:
                action, _ = agent.model.predict(obs, deterministic=True)
                obs, reward, done, info = env.step(action)
                episode_reward += reward
                
                if action == 1:  # Hint action
                    hint_count += 1
                
                if done:
                    rewards.append(episode_reward)
                    hint_counts.append(hint_count)
                    success_rates.append(1 if info.get('success', False) else 0)
                    break
        
        return {
            'avg_hints_per_episode': float(np.mean(hint_counts)),
            'success_rate': float(np.mean(success_rates)),
            'hint_efficiency': float(np.mean(success_rates) / (np.mean(hint_counts) + 1e-6)),
            'reward_consistency': float(1.0 - (np.std(rewards) / (np.mean(rewards) + 1e-6)))
        }
    
    def run_evaluation(self, personas: List[str], episodes: int = 1000) -> Dict[str, Any]:
        """Run evaluation for all specified personas."""
        logger.info(f"Starting RL evaluation for personas: {personas}")
        
        all_results = []
        for persona in personas:
            result = self.evaluate_persona(persona, episodes)
            all_results.append(result)
        
        # Calculate comparative metrics
        comparative_metrics = self._calculate_comparative_metrics(all_results)
        
        evaluation_results = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'config': self.config,
            'personas': personas,
            'episodes_per_persona': episodes,
            'individual_results': all_results,
            'comparative_metrics': comparative_metrics
        }
        
        return evaluation_results
    
    def _calculate_comparative_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate metrics comparing different personas."""
        rewards = [r['mean_reward'] for r in results]
        success_rates = [r['metrics']['success_rate'] for r in results]
        
        return {
            'best_performing_persona': results[np.argmax(rewards)]['persona'],
            'highest_success_rate': max(success_rates),
            'reward_variance': float(np.var(rewards)),
            'adaptation_effectiveness': float(np.mean(success_rates))
        }


def main():
    """Main evaluation function."""
    parser = argparse.ArgumentParser(description='Evaluate RL Hint Agent')
    parser.add_argument('--agents', nargs='+', 
                       default=['novice', 'intermediate', 'optimal'],
                       help='Learner personas to evaluate')
    parser.add_argument('--episodes', type=int, default=1000,
                       help='Number of episodes per persona')
    parser.add_argument('--config', type=str, 
                       default='config/rl-evaluation-config.json',
                       help='Configuration file path')
    parser.add_argument('--output', type=str, 
                       default='results/rl-performance.json',
                       help='Output file path')
    
    args = parser.parse_args()
    
    # Create output directory
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    # Run evaluation
    evaluator = RLEvaluator(args.config)
    results = evaluator.run_evaluation(args.agents, args.episodes)
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Evaluation complete. Results saved to {args.output}")
    
    # Print summary
    print("\n" + "="*50)
    print("RL AGENT EVALUATION SUMMARY")
    print("="*50)
    
    for result in results['individual_results']:
        persona = result['persona']
        reward = result['mean_reward']
        success_rate = result['metrics']['success_rate']
        avg_hints = result['metrics']['avg_hints_per_episode']
        
        print(f"{persona.upper():>12}: Reward={reward:6.3f}, Success={success_rate:.1%}, Hints={avg_hints:.1f}")
    
    print(f"\nBest Performing: {results['comparative_metrics']['best_performing_persona']}")
    print(f"Overall Success Rate: {results['comparative_metrics']['adaptation_effectiveness']:.1%}")


if __name__ == "__main__":
    main()
