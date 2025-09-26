#!/usr/bin/env python3
"""
Threat Simulation Engine Evaluation Script

This script evaluates the Threat Simulation Engine's ability to generate
realistic attack scenarios and validate applied defenses.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

import pandas as pd
import yaml
from kubernetes import client, config

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

from threat_simulation.engine import ThreatSimulationEngine
from threat_simulation.mitre_mapping import MITREMapper
from threat_simulation.playbooks import PlaybookManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatEvaluator:
    """Evaluates threat simulation engine performance and realism."""
    
    def __init__(self, config_path: str):
        """Initialize evaluator with configuration."""
        self.config = self._load_config(config_path)
        self.engine = ThreatSimulationEngine(self.config)
        self.mitre_mapper = MITREMapper()
        self.playbook_manager = PlaybookManager()
        self.results = {}
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load evaluation configuration."""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def evaluate_playbook(self, playbook_name: str, target_cluster: str) -> Dict[str, Any]:
        """Evaluate a specific attack playbook."""
        logger.info(f"Evaluating playbook: {playbook_name}")
        
        # Load playbook
        playbook = self.playbook_manager.get_playbook(playbook_name)
        
        # Execute simulation
        simulation_result = self.engine.execute_playbook(
            playbook=playbook,
            target_cluster=target_cluster,
            dry_run=True  # Safety for evaluation
        )
        
        # Calculate metrics
        metrics = self._calculate_playbook_metrics(playbook, simulation_result)
        
        return {
            'playbook': playbook_name,
            'target_cluster': target_cluster,
            'simulation_result': simulation_result,
            'metrics': metrics
        }
    
    def _calculate_playbook_metrics(self, playbook: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, float]:
        """Calculate metrics for playbook execution."""
        # MITRE ATT&CK coverage
        mitre_techniques = playbook.get('mitre_techniques', [])
        coverage_score = len(mitre_techniques) / 10.0  # Normalize to 0-1
        
        # Realism score based on execution success
        execution_success = result.get('success_rate', 0.0)
        
        # Complexity score
        steps = len(playbook.get('steps', []))
        complexity_score = min(steps / 20.0, 1.0)  # Normalize to 0-1
        
        # Detection evasion score
        evasion_score = result.get('detection_evasion_rate', 0.0)
        
        return {
            'mitre_coverage': coverage_score,
            'execution_success': execution_success,
            'complexity_score': complexity_score,
            'evasion_score': evasion_score,
            'overall_realism': (coverage_score + execution_success + complexity_score + evasion_score) / 4.0
        }
    
    def evaluate_all_playbooks(self, target_cluster: str) -> Dict[str, Any]:
        """Evaluate all available playbooks."""
        logger.info("Evaluating all threat simulation playbooks...")
        
        playbooks = self.playbook_manager.list_playbooks()
        results = []
        
        for playbook_name in playbooks:
            try:
                result = self.evaluate_playbook(playbook_name, target_cluster)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to evaluate {playbook_name}: {e}")
                results.append({
                    'playbook': playbook_name,
                    'error': str(e),
                    'metrics': {'overall_realism': 0.0}
                })
        
        # Calculate aggregate metrics
        aggregate_metrics = self._calculate_aggregate_metrics(results)
        
        return {
            'timestamp': pd.Timestamp.now().isoformat(),
            'target_cluster': target_cluster,
            'total_playbooks': len(playbooks),
            'successful_evaluations': len([r for r in results if 'error' not in r]),
            'individual_results': results,
            'aggregate_metrics': aggregate_metrics
        }
    
    def _calculate_aggregate_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate aggregate metrics across all playbooks."""
        successful_results = [r for r in results if 'error' not in r]
        
        if not successful_results:
            return {'error': 'No successful evaluations'}
        
        realism_scores = [r['metrics']['overall_realism'] for r in successful_results]
        coverage_scores = [r['metrics']['mitre_coverage'] for r in successful_results]
        execution_scores = [r['metrics']['execution_success'] for r in successful_results]
        
        return {
            'avg_realism_score': float(sum(realism_scores) / len(realism_scores)),
            'avg_mitre_coverage': float(sum(coverage_scores) / len(coverage_scores)),
            'avg_execution_success': float(sum(execution_scores) / len(execution_scores)),
            'best_playbook': successful_results[max(range(len(realism_scores)), key=lambda i: realism_scores[i])]['playbook'],
            'realism_consistency': float(1.0 - (max(realism_scores) - min(realism_scores)))
        }
    
    def evaluate_mitre_coverage(self) -> Dict[str, Any]:
        """Evaluate MITRE ATT&CK framework coverage."""
        logger.info("Evaluating MITRE ATT&CK coverage...")
        
        playbooks = self.playbook_manager.list_playbooks()
        all_techniques = set()
        
        for playbook_name in playbooks:
            playbook = self.playbook_manager.get_playbook(playbook_name)
            techniques = playbook.get('mitre_techniques', [])
            all_techniques.update(techniques)
        
        # Get all MITRE techniques
        all_mitre_techniques = self.mitre_mapper.get_all_techniques()
        
        coverage_analysis = {
            'total_mitre_techniques': len(all_mitre_techniques),
            'covered_techniques': len(all_techniques),
            'coverage_percentage': len(all_techniques) / len(all_mitre_techniques) * 100,
            'covered_technique_list': list(all_techniques),
            'missing_techniques': list(set(all_mitre_techniques) - all_techniques)
        }
        
        return coverage_analysis
    
    def run_comprehensive_evaluation(self, target_cluster: str) -> Dict[str, Any]:
        """Run comprehensive threat simulation evaluation."""
        logger.info("Starting comprehensive threat simulation evaluation...")
        
        # Evaluate all playbooks
        playbook_results = self.evaluate_all_playbooks(target_cluster)
        
        # Evaluate MITRE coverage
        mitre_coverage = self.evaluate_mitre_coverage()
        
        # Combine results
        comprehensive_results = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'evaluation_type': 'comprehensive_threat_simulation',
            'target_cluster': target_cluster,
            'playbook_evaluation': playbook_results,
            'mitre_coverage_analysis': mitre_coverage,
            'summary': {
                'total_playbooks_evaluated': playbook_results['total_playbooks'],
                'successful_evaluations': playbook_results['successful_evaluations'],
                'avg_realism_score': playbook_results['aggregate_metrics'].get('avg_realism_score', 0.0),
                'mitre_coverage_percentage': mitre_coverage['coverage_percentage']
            }
        }
        
        return comprehensive_results


def main():
    """Main evaluation function."""
    parser = argparse.ArgumentParser(description='Evaluate Threat Simulation Engine')
    parser.add_argument('--playbooks', nargs='+', default=['all'],
                       help='Specific playbooks to evaluate (default: all)')
    parser.add_argument('--target-cluster', type=str, default='test-cluster',
                       help='Target cluster for evaluation')
    parser.add_argument('--config', type=str, 
                       default='config/threat-evaluation-config.json',
                       help='Configuration file path')
    parser.add_argument('--output', type=str, 
                       default='results/threat-realism.json',
                       help='Output file path')
    
    args = parser.parse_args()
    
    # Create output directory
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    # Run evaluation
    evaluator = ThreatEvaluator(args.config)
    
    if args.playbooks == ['all']:
        results = evaluator.run_comprehensive_evaluation(args.target_cluster)
    else:
        # Evaluate specific playbooks
        individual_results = []
        for playbook in args.playbooks:
            result = evaluator.evaluate_playbook(playbook, args.target_cluster)
            individual_results.append(result)
        
        results = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'evaluation_type': 'specific_playbooks',
            'target_cluster': args.target_cluster,
            'playbooks': args.playbooks,
            'results': individual_results
        }
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Evaluation complete. Results saved to {args.output}")
    
    # Print summary
    print("\n" + "="*60)
    print("THREAT SIMULATION EVALUATION SUMMARY")
    print("="*60)
    
    if 'summary' in results:
        summary = results['summary']
        print(f"Total Playbooks Evaluated: {summary['total_playbooks_evaluated']}")
        print(f"Successful Evaluations: {summary['successful_evaluations']}")
        print(f"Average Realism Score: {summary['avg_realism_score']:.3f}")
        print(f"MITRE Coverage: {summary['mitre_coverage_percentage']:.1f}%")
    else:
        print(f"Evaluated {len(results['results'])} playbooks")
        for result in results['results']:
            playbook = result['playbook']
            realism = result['metrics']['overall_realism']
            print(f"{playbook:>20}: Realism={realism:.3f}")


if __name__ == "__main__":
    main()
