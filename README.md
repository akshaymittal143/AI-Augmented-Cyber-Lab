# AI-Augmented Cyber Lab: Reproducibility Repository

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-v1.24+-blue.svg)](https://kubernetes.io/)

This repository contains the complete implementation of the AI-Augmented Cyber Lab system for enhancing cloud-native security education through adaptive feedback and threat simulation, as described in our research paper.

## Table of Contents

- [System Architecture](#system-architecture)
- [Quick Start](#quick-start)
- [Components](#components)
- [Installation](#installation)
- [Usage](#usage)
- [Evaluation](#evaluation)
- [Contributing](#contributing)
- [Citation](#citation)

## System Architecture

The AI-augmented cyber lab integrates three core components:

1. **LLM Analyzer** - Semantic security analysis of student artifacts (Dockerfiles, YAML manifests, Terraform configurations)
2. **RL Hint Agent** - Adaptive pedagogical scaffolding using reinforcement learning
3. **Threat Simulation Engine** - Realistic attack scenarios within isolated Kubernetes environments

All components communicate via an event-driven architecture deployed on Kubernetes clusters.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/akshaymittal143/AI-Augmented-Cyber-Lab.git
cd AI-Augmented-Cyber-Lab

# Install dependencies
pip install -r requirements.txt

# Set up Kubernetes cluster (using kind for local development)
# Note: setup-cluster.sh script to be added in future release
kind create cluster --name cyber-lab

# Deploy the system
kubectl apply -f k8s/

# Run the evaluation (requires dataset - see evaluation section)
# python evaluation/run_evaluation.py
```

## Components

### LLM Analyzer (`src/llm_analyzer/`)
- Security misconfiguration detection
- Few-shot prompt engineering for cloud-native artifacts
- Schema validation and expert review integration
- 92% F1-score on real-world artifact corpus

### RL Hint Agent (`src/rl_agent/`)
- Adaptive scaffolding based on student competence
- Q-learning with custom reward functions
- Multi-armed bandit for hint timing optimization
- A/B testing against expert-authored flows

### Threat Simulation Engine (`src/threat_simulation/`)
- Production-grade attack playbooks
- MITRE ATT&CK framework alignment
- Container escape and privilege escalation scenarios
- Kubernetes RBAC bypass techniques

## Installation

### Prerequisites

- Python 3.8+
- Docker 20.10+
- Kubernetes 1.24+
- kubectl configured
- Helm 3.0+

### Environment Setup

1. **Create Python virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables:**
```bash
cp env.example .env
# Edit .env with your configuration - see below for required settings
```

### Environment Configuration

The system requires several environment variables to be configured in `.env`. Here are the key settings you need to update:

#### **Required - AI Model Configuration**
```bash
# REQUIRED: Get from OpenAI (https://platform.openai.com/api-keys)
OPENAI_API_KEY=your-actual-openai-api-key-here

# Optional: Anthropic API for alternative models
ANTHROPIC_API_KEY=your-anthropic-api-key-here

# Model settings (defaults shown)
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048
```

#### **Database Configuration**
```bash
# PostgreSQL for persistent storage
DATABASE_URL=postgresql://user:password@localhost:5432/cyber_lab

# Redis for caching and session management
REDIS_URL=redis://localhost:6379/0
```

#### **Security Settings**
```bash
# REQUIRED: Generate a secure random key
SECRET_KEY=your-secure-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
```

#### **System Configuration**
```bash
# Kubernetes settings
KUBECONFIG_PATH=~/.kube/config
NAMESPACE=ai-cyber-lab
CLUSTER_NAME=cyber-lab-cluster

# Lab capacity and behavior
MAX_STUDENTS_PER_LAB=50
SESSION_TIMEOUT_MINUTES=60
HINT_COOLDOWN_SECONDS=30

# Development settings
DEBUG=true
LOG_LEVEL=INFO
```

> **Important**: You MUST set `OPENAI_API_KEY` to use the LLM analyzer. Without this, the core security analysis functionality will not work.

4. **Set up Kubernetes cluster:**
```bash
# For local development with kind
./scripts/setup-local-cluster.sh

# For production deployment
./scripts/setup-production-cluster.sh
```

## Usage

### Running Individual Components

```bash
# Start LLM Analyzer
python -m llm_analyzer.main --config config/llm-config.yaml

# Start RL Hint Agent
python -m rl_agent.main --config config/rl-config.yaml

# Start Threat Simulation Engine
python -m threat_simulation.main --config config/threat-config.yaml
```

### Running the Complete System

```bash
# Deploy all components
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmaps/
kubectl apply -f k8s/deployments/
kubectl apply -f k8s/services/

# Monitor deployment
kubectl get pods -n ai-cyber-lab --watch
```

### Web Interface

Access the student interface at `http://localhost:8080` after deployment.

## Evaluation

The repository includes comprehensive evaluation scripts and datasets:

### LLM Analyzer Evaluation
```bash
python evaluation/llm_evaluation.py \
  --dataset datasets/cloud-native-artifacts-1500.json \
  --model gpt-4 \
  --output results/llm-accuracy.json
```

### RL Agent Evaluation
```bash
python evaluation/rl_evaluation.py \
  --agents novice,intermediate,optimal \
  --episodes 1000 \
  --output results/rl-performance.json
```

### Threat Simulation Evaluation
```bash
python evaluation/threat_evaluation.py \
  --playbooks all \
  --target-cluster test-cluster \
  --output results/threat-realism.json
```

## Lab Scenarios

The system includes four comprehensive lab modules:

1. **Container Hardening** - Dockerfile security, non-root users, minimal images
2. **Supply Chain Security** - SBOM generation, Trivy scans, dependency auditing  
3. **Kubernetes RBAC** - Access control, role scoping, NetworkPolicies
4. **GitOps Security** - IaC governance, secure Argo CD, manifest validation

Each module includes:
- Pre-configured vulnerable environments
- Progressive difficulty levels
- Automated assessment criteria
- Real-time threat simulation

## Research Validation

This implementation reproduces the results reported in our paper:

- **LLM Analyzer Accuracy**: 92% F1-score on 1,500 real-world artifacts
- **RL Agent Performance**: >85% confidence in adaptive hint delivery
- **System Scalability**: Tested on multi-node Kubernetes clusters
- **Educational Effectiveness**: Validated through expert review (4.4/5 average rating)

## Development

### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# End-to-end tests
pytest tests/e2e/
```

### Code Quality
```bash
# Linting
flake8 src/
black src/

# Type checking
mypy src/
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use this code in your research, please cite our paper:

```bibtex
@inproceedings{ai-augmented-cyber-lab-2025,
  title={AI-Augmented Cyber Labs: Enhancing Cloud-Native Security Education through Adaptive Feedback and Threat Simulation},
  author={Akshay Mittal and Harsh Shah and Pragya Keshap},
  booktitle={Proceedings of the ACM Conference on Computer Science Education},
  year={2025},
  publisher={ACM}
}
```

## Contact

For questions or support, please open an issue or contact:
- Primary Author: akshay.mittal@ieee.org
- Co-Author: hs634@cornell.edu
- Co-Author: pragyakeshap@ieee.org

## 🙏 Acknowledgments

- Thank you to the cybersecurity education community for feedback and validation
- Special thanks to contributors who helped with evaluation datasets
- Built with support from [funding acknowledgments]
