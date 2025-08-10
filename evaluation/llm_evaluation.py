"""
LLM Analyzer Evaluation System

Reproduces the 94% accuracy evaluation results reported in the paper.
Evaluates LLM security analysis accuracy on 1,500 real-world cloud-native artifacts.
"""

import json
import logging
import asyncio
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from ..src.llm_analyzer import LLMSecurityAnalyzer, ArtifactType, SecurityFinding


@dataclass
class EvaluationCase:
    """Single evaluation case with ground truth."""
    artifact_id: str
    artifact_type: ArtifactType
    content: str
    ground_truth_findings: List[Dict]
    expert_annotations: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


@dataclass
class EvaluationMetrics:
    """Evaluation metrics for LLM analyzer performance."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    confusion_matrix: List[List[int]]
    category_breakdown: Dict[str, Dict[str, float]] = field(default_factory=dict)


class LLMAnalyzerEvaluator:
    """
    Comprehensive evaluation system for LLM security analyzer.
    
    Reproduces paper results:
    - 94% accuracy on 1,500 real-world artifacts
    - Breakdown by artifact type and vulnerability category
    - Confidence score validation
    """
    
    def __init__(self, analyzer: LLMSecurityAnalyzer):
        self.analyzer = analyzer
        self.logger = logging.getLogger(__name__)
        
        # Evaluation datasets
        self.evaluation_cases: List[EvaluationCase] = []
        self.results_cache: Dict[str, Dict] = {}
    
    def load_evaluation_dataset(self, dataset_path: str):
        """Load curated evaluation dataset with ground truth annotations."""
        try:
            with open(dataset_path, 'r') as f:
                dataset = json.load(f)
            
            self.evaluation_cases = []
            
            for case_data in dataset['evaluation_cases']:
                case = EvaluationCase(
                    artifact_id=case_data['artifact_id'],
                    artifact_type=ArtifactType(case_data['artifact_type']),
                    content=case_data['content'],
                    ground_truth_findings=case_data['ground_truth_findings'],
                    expert_annotations=case_data.get('expert_annotations', {}),
                    metadata=case_data.get('metadata', {})
                )
                self.evaluation_cases.append(case)
            
            self.logger.info(f"Loaded {len(self.evaluation_cases)} evaluation cases")
            
        except Exception as e:
            self.logger.error(f"Failed to load evaluation dataset: {str(e)}")
            raise
    
    async def run_comprehensive_evaluation(self) -> EvaluationMetrics:
        """
        Run complete evaluation reproducing paper results.
        
        Returns:
            EvaluationMetrics with detailed performance analysis
        """
        if not self.evaluation_cases:
            raise ValueError("No evaluation cases loaded. Call load_evaluation_dataset() first.")
        
        self.logger.info(f"Starting comprehensive evaluation on {len(self.evaluation_cases)} cases")
        
        # Run analysis on all cases
        predictions = []
        ground_truths = []
        category_results = {}
        
        for i, case in enumerate(self.evaluation_cases):
            if i % 100 == 0:
                self.logger.info(f"Processed {i}/{len(self.evaluation_cases)} cases")
            
            try:
                # Run LLM analysis
                result = self.analyzer.analyze_artifact(
                    content=case.content,
                    artifact_type=case.artifact_type
                )
                
                # Compare with ground truth
                predicted_findings = self._extract_finding_labels(result.findings)
                actual_findings = self._extract_ground_truth_labels(case.ground_truth_findings)
                
                # Binary classification for each vulnerability type
                for vuln_type in self._get_all_vulnerability_types():
                    pred_has_vuln = vuln_type in predicted_findings
                    actual_has_vuln = vuln_type in actual_findings
                    
                    predictions.append(1 if pred_has_vuln else 0)
                    ground_truths.append(1 if actual_has_vuln else 0)
                    
                    # Track by category
                    if vuln_type not in category_results:
                        category_results[vuln_type] = {'predictions': [], 'ground_truth': []}
                    
                    category_results[vuln_type]['predictions'].append(1 if pred_has_vuln else 0)
                    category_results[vuln_type]['ground_truth'].append(1 if actual_has_vuln else 0)
                
                # Cache results
                self.results_cache[case.artifact_id] = {
                    'predicted_findings': predicted_findings,
                    'actual_findings': actual_findings,
                    'analysis_result': result,
                    'evaluation_case': case
                }
                
            except Exception as e:
                self.logger.error(f"Evaluation failed for case {case.artifact_id}: {str(e)}")
                continue
        
        # Calculate overall metrics
        accuracy = accuracy_score(ground_truths, predictions)
        precision = precision_score(ground_truths, predictions, average='binary', zero_division=0)
        recall = recall_score(ground_truths, predictions, average='binary', zero_division=0)
        f1 = f1_score(ground_truths, predictions, average='binary', zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(ground_truths, predictions)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        # Category-wise breakdown
        category_breakdown = {}
        for category, data in category_results.items():
            if len(data['predictions']) > 0:
                cat_accuracy = accuracy_score(data['ground_truth'], data['predictions'])
                cat_precision = precision_score(data['ground_truth'], data['predictions'], zero_division=0)
                cat_recall = recall_score(data['ground_truth'], data['predictions'], zero_division=0)
                cat_f1 = f1_score(data['ground_truth'], data['predictions'], zero_division=0)
                
                category_breakdown[category] = {
                    'accuracy': cat_accuracy,
                    'precision': cat_precision,
                    'recall': cat_recall,
                    'f1_score': cat_f1,
                    'sample_count': len(data['predictions'])
                }
        
        metrics = EvaluationMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            true_positives=int(tp),
            false_positives=int(fp),
            false_negatives=int(fn),
            true_negatives=int(tn),
            confusion_matrix=cm.tolist(),
            category_breakdown=category_breakdown
        )
        
        self.logger.info(f"Evaluation completed. Overall accuracy: {accuracy:.1%}")
        return metrics
    
    def _extract_finding_labels(self, findings: List[SecurityFinding]) -> List[str]:
        """Extract vulnerability type labels from LLM findings."""
        labels = []
        for finding in findings:
            # Map finding categories to standard vulnerability types
            vuln_type = self._normalize_vulnerability_type(finding.category)
            if vuln_type:
                labels.append(vuln_type)
        return list(set(labels))  # Remove duplicates
    
    def _extract_ground_truth_labels(self, ground_truth_findings: List[Dict]) -> List[str]:
        """Extract vulnerability type labels from ground truth annotations."""
        labels = []
        for finding in ground_truth_findings:
            vuln_type = self._normalize_vulnerability_type(finding.get('category', ''))
            if vuln_type:
                labels.append(vuln_type)
        return list(set(labels))  # Remove duplicates
    
    def _normalize_vulnerability_type(self, category: str) -> Optional[str]:
        """Normalize vulnerability category to standard types."""
        category_lower = category.lower()
        
        # Standard vulnerability type mappings
        mappings = {
            'privilege escalation': 'privilege_escalation',
            'privilege_escalation': 'privilege_escalation',
            'secrets management': 'secrets_management',
            'secret management': 'secrets_management',
            'secrets_management': 'secrets_management',
            'container security': 'container_security',
            'container_security': 'container_security',
            'network security': 'network_security',
            'network_security': 'network_security',
            'access control': 'access_control',
            'access_control': 'access_control',
            'supply chain security': 'supply_chain',
            'supply_chain': 'supply_chain',
            'configuration': 'misconfiguration',
            'misconfiguration': 'misconfiguration',
            'hardcoded credentials': 'secrets_management',
            'exposed secrets': 'secrets_management',
            'insecure defaults': 'misconfiguration',
            'missing security controls': 'access_control'
        }
        
        return mappings.get(category_lower)
    
    def _get_all_vulnerability_types(self) -> List[str]:
        """Get all vulnerability types for evaluation."""
        return [
            'privilege_escalation',
            'secrets_management', 
            'container_security',
            'network_security',
            'access_control',
            'supply_chain',
            'misconfiguration'
        ]
    
    def run_artifact_type_evaluation(self) -> Dict[str, EvaluationMetrics]:
        """Run evaluation broken down by artifact type."""
        results = {}
        
        for artifact_type in ArtifactType:
            type_cases = [case for case in self.evaluation_cases if case.artifact_type == artifact_type]
            
            if not type_cases:
                continue
            
            self.logger.info(f"Evaluating {len(type_cases)} {artifact_type.value} cases")
            
            # Run evaluation for this artifact type
            type_evaluator = LLMAnalyzerEvaluator(self.analyzer)
            type_evaluator.evaluation_cases = type_cases
            
            type_metrics = asyncio.run(type_evaluator.run_comprehensive_evaluation())
            results[artifact_type.value] = type_metrics
        
        return results
    
    def generate_evaluation_report(self, metrics: EvaluationMetrics) -> Dict:
        """Generate comprehensive evaluation report."""
        report = {
            "evaluation_summary": {
                "total_cases_evaluated": len(self.evaluation_cases),
                "evaluation_timestamp": datetime.utcnow().isoformat(),
                "overall_accuracy": f"{metrics.accuracy:.1%}",
                "meets_paper_benchmark": metrics.accuracy >= 0.94
            },
            
            "performance_metrics": {
                "accuracy": metrics.accuracy,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1_score": metrics.f1_score
            },
            
            "confusion_matrix": {
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "false_negatives": metrics.false_negatives,
                "true_negatives": metrics.true_negatives,
                "matrix": metrics.confusion_matrix
            },
            
            "vulnerability_category_breakdown": metrics.category_breakdown,
            
            "paper_comparison": {
                "paper_reported_accuracy": 0.94,
                "achieved_accuracy": metrics.accuracy,
                "accuracy_difference": metrics.accuracy - 0.94,
                "performance_assessment": "Meets benchmark" if metrics.accuracy >= 0.94 else "Below benchmark"
            },
            
            "dataset_composition": self._analyze_dataset_composition(),
            
            "recommendations": self._generate_recommendations(metrics)
        }
        
        return report
    
    def _analyze_dataset_composition(self) -> Dict:
        """Analyze composition of evaluation dataset."""
        if not self.evaluation_cases:
            return {}
        
        type_counts = {}
        for case in self.evaluation_cases:
            artifact_type = case.artifact_type.value
            type_counts[artifact_type] = type_counts.get(artifact_type, 0) + 1
        
        return {
            "total_cases": len(self.evaluation_cases),
            "artifact_type_distribution": type_counts,
            "average_findings_per_case": np.mean([
                len(case.ground_truth_findings) for case in self.evaluation_cases
            ]) if self.evaluation_cases else 0
        }
    
    def _generate_recommendations(self, metrics: EvaluationMetrics) -> List[str]:
        """Generate recommendations based on evaluation results."""
        recommendations = []
        
        if metrics.accuracy < 0.94:
            recommendations.append("Consider fine-tuning prompt engineering to improve accuracy")
            recommendations.append("Review and expand few-shot examples in prompts")
        
        if metrics.precision < 0.85:
            recommendations.append("Reduce false positives by improving specificity of prompts")
        
        if metrics.recall < 0.85:
            recommendations.append("Improve sensitivity by expanding vulnerability detection patterns")
        
        # Category-specific recommendations
        for category, cat_metrics in metrics.category_breakdown.items():
            if cat_metrics['accuracy'] < 0.80:
                recommendations.append(f"Focus improvement efforts on {category} detection")
        
        if not recommendations:
            recommendations.append("Performance meets benchmarks - consider expanding evaluation dataset")
        
        return recommendations
    
    def export_results(self, metrics: EvaluationMetrics, output_path: str, format: str = "json"):
        """Export evaluation results to file."""
        report = self.generate_evaluation_report(metrics)
        
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        elif format == "csv":
            import pandas as pd
            
            # Create summary DataFrame
            summary_data = []
            for category, cat_metrics in metrics.category_breakdown.items():
                summary_data.append({
                    'category': category,
                    'accuracy': cat_metrics['accuracy'],
                    'precision': cat_metrics['precision'],
                    'recall': cat_metrics['recall'],
                    'f1_score': cat_metrics['f1_score'],
                    'sample_count': cat_metrics['sample_count']
                })
            
            df = pd.DataFrame(summary_data)
            df.to_csv(output_path, index=False)
        
        self.logger.info(f"Evaluation results exported to {output_path}")
    
    def run_confidence_analysis(self) -> Dict:
        """Analyze confidence scores vs accuracy correlation."""
        if not self.results_cache:
            raise ValueError("No cached results available. Run evaluation first.")
        
        confidence_bins = {'high': [], 'medium': [], 'low': []}
        
        for result_data in self.results_cache.values():
            analysis_result = result_data['analysis_result']
            
            # Calculate average confidence across findings
            if analysis_result.findings:
                avg_confidence = np.mean([f.confidence for f in analysis_result.findings])
                
                # Bin by confidence level
                if avg_confidence >= 0.8:
                    bin_name = 'high'
                elif avg_confidence >= 0.5:
                    bin_name = 'medium'
                else:
                    bin_name = 'low'
                
                # Check if prediction was correct (simplified)
                predicted = result_data['predicted_findings']
                actual = result_data['actual_findings']
                correct = len(set(predicted).intersection(set(actual))) > 0
                
                confidence_bins[bin_name].append(correct)
        
        # Calculate accuracy for each confidence bin
        analysis = {}
        for bin_name, results in confidence_bins.items():
            if results:
                accuracy = sum(results) / len(results)
                analysis[f'{bin_name}_confidence'] = {
                    'accuracy': accuracy,
                    'sample_count': len(results),
                    'confidence_range': self._get_confidence_range(bin_name)
                }
        
        return analysis
    
    def _get_confidence_range(self, bin_name: str) -> str:
        """Get confidence range description for bin."""
        ranges = {
            'high': '0.8 - 1.0',
            'medium': '0.5 - 0.8',
            'low': '0.0 - 0.5'
        }
        return ranges.get(bin_name, 'unknown')
