#!/usr/bin/env python3
"""
Expert Evaluation Script

This script facilitates expert evaluation of the AI-Augmented Cyber Lab system
as described in the paper, collecting ratings and feedback from domain experts.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

import pandas as pd

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

from llm_analyzer.analyzer import LLMAnalyzer
from rl_agent.agent import RLHintAgent
from threat_simulation.engine import ThreatSimulationEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExpertEvaluator:
    """Manages expert evaluation of the AI-Augmented Cyber Lab system."""
    
    def __init__(self, config_path: str):
        """Initialize evaluator with configuration."""
        self.config = self._load_config(config_path)
        self.evaluation_criteria = self.config.get('evaluation_criteria', {})
        self.results = {}
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load evaluation configuration."""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def create_evaluation_interface(self) -> Dict[str, Any]:
        """Create the expert evaluation interface with sample scenarios."""
        logger.info("Creating expert evaluation interface...")
        
        # Sample artifacts for evaluation
        sample_artifacts = self._get_sample_artifacts()
        
        # Sample hint scenarios
        hint_scenarios = self._get_hint_scenarios()
        
        # Sample threat simulations
        threat_scenarios = self._get_threat_scenarios()
        
        evaluation_interface = {
            'timestamp': datetime.now().isoformat(),
            'evaluation_criteria': self.evaluation_criteria,
            'sample_artifacts': sample_artifacts,
            'hint_scenarios': hint_scenarios,
            'threat_scenarios': threat_scenarios,
            'rating_scale': {
                'min': 1,
                'max': 5,
                'labels': {
                    1: 'Poor',
                    2: 'Below Average', 
                    3: 'Average',
                    4: 'Good',
                    5: 'Excellent'
                }
            }
        }
        
        return evaluation_interface
    
    def _get_sample_artifacts(self) -> List[Dict[str, Any]]:
        """Get sample artifacts for expert evaluation."""
        return [
            {
                'type': 'Dockerfile',
                'content': '''
FROM ubuntu:latest
USER root
COPY . /app
RUN chmod 777 /app
EXPOSE 8080
CMD ["python", "app.py"]
                ''',
                'expected_issues': [
                    'Running as root user',
                    'Overly permissive file permissions',
                    'Using latest tag',
                    'No security scanning'
                ]
            },
            {
                'type': 'Kubernetes Deployment',
                'content': '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
      - name: web-app
        image: web-app:latest
        ports:
        - containerPort: 8080
        securityContext:
          runAsUser: 0
          privileged: true
                ''',
                'expected_issues': [
                    'Running as root (runAsUser: 0)',
                    'Privileged container',
                    'Using latest tag',
                    'No resource limits'
                ]
            },
            {
                'type': 'Terraform Configuration',
                'content': '''
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = false
  block_public_policy = false
}
                ''',
                'expected_issues': [
                    'Public access not blocked',
                    'No encryption specified',
                    'No versioning enabled'
                ]
            }
        ]
    
    def _get_hint_scenarios(self) -> List[Dict[str, Any]]:
        """Get sample hint scenarios for expert evaluation."""
        return [
            {
                'scenario': 'Novice student struggling with Dockerfile security',
                'student_attempts': 3,
                'time_spent': 15,
                'current_artifact': 'Dockerfile with root user and no security measures',
                'hint_provided': 'Consider running containers as non-root users for better security',
                'evaluation_points': [
                    'Appropriateness of hint timing',
                    'Clarity of guidance',
                    'Pedagogical value',
                    'Not giving away the answer'
                ]
            },
            {
                'scenario': 'Intermediate student working on Kubernetes RBAC',
                'student_attempts': 1,
                'time_spent': 5,
                'current_artifact': 'Kubernetes deployment with overly broad permissions',
                'hint_provided': 'Review the principle of least privilege when configuring service accounts',
                'evaluation_points': [
                    'Appropriateness of hint timing',
                    'Clarity of guidance', 
                    'Pedagogical value',
                    'Not giving away the answer'
                ]
            }
        ]
    
    def _get_threat_scenarios(self) -> List[Dict[str, Any]]:
        """Get sample threat simulation scenarios for expert evaluation."""
        return [
            {
                'scenario': 'Container Escape Attack',
                'description': 'Simulation of container escape vulnerability exploitation',
                'target_environment': 'Misconfigured Kubernetes pod with privileged container',
                'attack_techniques': ['T1611 - Escape to Host', 'T1055 - Process Injection'],
                'expected_outcome': 'Successful container escape and host access',
                'evaluation_points': [
                    'Realism of attack scenario',
                    'Appropriateness of target environment',
                    'Educational value',
                    'Safety of simulation'
                ]
            },
            {
                'scenario': 'RBAC Privilege Escalation',
                'description': 'Simulation of Kubernetes RBAC bypass and privilege escalation',
                'target_environment': 'Kubernetes cluster with overly permissive RBAC policies',
                'attack_techniques': ['T1078 - Valid Accounts', 'T1484 - Domain Policy Modification'],
                'expected_outcome': 'Successful privilege escalation to cluster-admin',
                'evaluation_points': [
                    'Realism of attack scenario',
                    'Appropriateness of target environment',
                    'Educational value',
                    'Safety of simulation'
                ]
            }
        ]
    
    def collect_expert_ratings(self, expert_id: str, ratings: Dict[str, Any]) -> Dict[str, Any]:
        """Collect and validate expert ratings."""
        logger.info(f"Collecting ratings from expert: {expert_id}")
        
        # Validate ratings
        validated_ratings = self._validate_ratings(ratings)
        
        expert_evaluation = {
            'expert_id': expert_id,
            'timestamp': datetime.now().isoformat(),
            'ratings': validated_ratings,
            'summary': self._calculate_expert_summary(validated_ratings)
        }
        
        return expert_evaluation
    
    def _validate_ratings(self, ratings: Dict[str, Any]) -> Dict[str, Any]:
        """Validate expert ratings against criteria."""
        validated = {}
        
        for category, rating in ratings.items():
            if isinstance(rating, dict):
                validated[category] = {}
                for criterion, score in rating.items():
                    if isinstance(score, (int, float)) and 1 <= score <= 5:
                        validated[category][criterion] = score
                    else:
                        logger.warning(f"Invalid rating for {category}.{criterion}: {score}")
                        validated[category][criterion] = None
            elif isinstance(rating, (int, float)) and 1 <= rating <= 5:
                validated[category] = rating
            else:
                logger.warning(f"Invalid rating for {category}: {rating}")
                validated[category] = None
        
        return validated
    
    def _calculate_expert_summary(self, ratings: Dict[str, Any]) -> Dict[str, float]:
        """Calculate summary statistics for expert ratings."""
        all_scores = []
        
        for category, rating in ratings.items():
            if isinstance(rating, dict):
                scores = [score for score in rating.values() if score is not None]
                all_scores.extend(scores)
            elif isinstance(rating, (int, float)) and rating is not None:
                all_scores.append(rating)
        
        if not all_scores:
            return {'average': 0.0, 'count': 0}
        
        return {
            'average': sum(all_scores) / len(all_scores),
            'count': len(all_scores),
            'min': min(all_scores),
            'max': max(all_scores)
        }
    
    def aggregate_expert_evaluations(self, evaluations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate multiple expert evaluations."""
        logger.info(f"Aggregating {len(evaluations)} expert evaluations...")
        
        if not evaluations:
            return {'error': 'No evaluations to aggregate'}
        
        # Collect all scores by category
        category_scores = {}
        
        for evaluation in evaluations:
            ratings = evaluation.get('ratings', {})
            for category, rating in ratings.items():
                if category not in category_scores:
                    category_scores[category] = []
                
                if isinstance(rating, dict):
                    for criterion, score in rating.items():
                        if score is not None:
                            category_scores[category].append(score)
                elif isinstance(rating, (int, float)) and rating is not None:
                    category_scores[category].append(rating)
        
        # Calculate aggregate statistics
        aggregate_results = {}
        all_scores = []
        
        for category, scores in category_scores.items():
            if scores:
                aggregate_results[category] = {
                    'average': sum(scores) / len(scores),
                    'count': len(scores),
                    'min': min(scores),
                    'max': max(scores),
                    'std': (sum((x - sum(scores)/len(scores))**2 for x in scores) / len(scores))**0.5
                }
                all_scores.extend(scores)
        
        # Overall statistics
        overall_stats = {
            'total_experts': len(evaluations),
            'total_ratings': len(all_scores),
            'overall_average': sum(all_scores) / len(all_scores) if all_scores else 0.0,
            'overall_min': min(all_scores) if all_scores else 0.0,
            'overall_max': max(all_scores) if all_scores else 0.0
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'individual_evaluations': evaluations,
            'category_aggregates': aggregate_results,
            'overall_statistics': overall_stats
        }
    
    def generate_evaluation_report(self, aggregated_results: Dict[str, Any]) -> str:
        """Generate a human-readable evaluation report."""
        report = []
        report.append("AI-AUGMENTED CYBER LAB - EXPERT EVALUATION REPORT")
        report.append("=" * 60)
        report.append("")
        
        # Overall statistics
        overall = aggregated_results.get('overall_statistics', {})
        report.append(f"Total Experts: {overall.get('total_experts', 0)}")
        report.append(f"Total Ratings: {overall.get('total_ratings', 0)}")
        report.append(f"Overall Average: {overall.get('overall_average', 0.0):.2f}/5.0")
        report.append("")
        
        # Category breakdown
        categories = aggregated_results.get('category_aggregates', {})
        report.append("CATEGORY BREAKDOWN:")
        report.append("-" * 30)
        
        for category, stats in categories.items():
            report.append(f"{category.replace('_', ' ').title()}:")
            report.append(f"  Average: {stats['average']:.2f}/5.0")
            report.append(f"  Range: {stats['min']:.1f} - {stats['max']:.1f}")
            report.append(f"  Count: {stats['count']} ratings")
            report.append("")
        
        return "\n".join(report)


def main():
    """Main evaluation function."""
    parser = argparse.ArgumentParser(description='Expert Evaluation Interface')
    parser.add_argument('--config', type=str, 
                       default='config/expert-evaluation-config.json',
                       help='Configuration file path')
    parser.add_argument('--mode', type=str, 
                       choices=['create-interface', 'collect-ratings', 'aggregate'],
                       default='create-interface',
                       help='Evaluation mode')
    parser.add_argument('--expert-id', type=str,
                       help='Expert ID for rating collection')
    parser.add_argument('--ratings-file', type=str,
                       help='File containing expert ratings (JSON)')
    parser.add_argument('--evaluations-file', type=str,
                       help='File containing multiple expert evaluations (JSON)')
    parser.add_argument('--output', type=str, 
                       default='results/expert-evaluation.json',
                       help='Output file path')
    
    args = parser.parse_args()
    
    # Create output directory
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    evaluator = ExpertEvaluator(args.config)
    
    if args.mode == 'create-interface':
        # Create evaluation interface
        interface = evaluator.create_evaluation_interface()
        
        with open(args.output, 'w') as f:
            json.dump(interface, f, indent=2)
        
        print("Expert evaluation interface created!")
        print(f"Interface saved to: {args.output}")
        print("\nPlease provide this interface to domain experts for evaluation.")
        
    elif args.mode == 'collect-ratings':
        # Collect individual expert ratings
        if not args.expert_id or not args.ratings_file:
            print("Error: --expert-id and --ratings-file are required for collect-ratings mode")
            return
        
        with open(args.ratings_file, 'r') as f:
            ratings = json.load(f)
        
        evaluation = evaluator.collect_expert_ratings(args.expert_id, ratings)
        
        with open(args.output, 'w') as f:
            json.dump(evaluation, f, indent=2)
        
        print(f"Expert {args.expert_id} evaluation collected!")
        print(f"Results saved to: {args.output}")
        
    elif args.mode == 'aggregate':
        # Aggregate multiple expert evaluations
        if not args.evaluations_file:
            print("Error: --evaluations-file is required for aggregate mode")
            return
        
        with open(args.evaluations_file, 'r') as f:
            evaluations = json.load(f)
        
        aggregated = evaluator.aggregate_expert_evaluations(evaluations)
        
        with open(args.output, 'w') as f:
            json.dump(aggregated, f, indent=2)
        
        # Generate and print report
        report = evaluator.generate_evaluation_report(aggregated)
        print(report)
        
        print(f"\nDetailed results saved to: {args.output}")


if __name__ == "__main__":
    main()
