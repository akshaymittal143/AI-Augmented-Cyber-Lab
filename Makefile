# AI-Augmented Cyber Lab - Research Automation
# Makefile for reproducible research and development workflows

.PHONY: help install test lint format clean docs docker k8s-deploy evaluate reproduce-results

# Default target
help: ## Show this help message
	@echo "AI-Augmented Cyber Lab - Research Automation"
	@echo "============================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Environment Setup
install: ## Install dependencies and set up development environment
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt || echo "requirements-dev.txt not found, skipping dev dependencies"
	@echo "✅ Dependencies installed successfully"

install-dev: ## Install development dependencies
	pip install pytest pytest-cov black flake8 mypy pre-commit
	pre-commit install
	@echo "✅ Development environment ready"

env-setup: ## Set up environment variables
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "📝 Created .env from .env.example - please update with your API keys"; \
	else \
		echo "✅ .env file already exists"; \
	fi

# Code Quality
format: ## Format code with Black
	black src/ tests/ evaluation/
	@echo "✅ Code formatted"

lint: ## Run linting checks
	flake8 src/ tests/ evaluation/
	mypy src/
	@echo "✅ Linting completed"

type-check: ## Run type checking
	mypy src/ --strict
	@echo "✅ Type checking completed"

# Testing
test: ## Run all tests
	pytest tests/ -v
	@echo "✅ All tests passed"

test-unit: ## Run unit tests only
	pytest tests/unit/ -v -m "unit"
	@echo "✅ Unit tests passed"

test-integration: ## Run integration tests
	pytest tests/integration/ -v -m "integration"
	@echo "✅ Integration tests passed"

test-coverage: ## Run tests with coverage report
	pytest tests/ --cov=src --cov-report=html --cov-report=term-missing
	@echo "📊 Coverage report generated in htmlcov/"

# Research Evaluation
evaluate-llm: ## Run LLM analyzer evaluation (reproduces 94% accuracy)
	python evaluation/llm_evaluation.py --dataset datasets/evaluation_corpus_1500.json
	@echo "📊 LLM evaluation completed"

evaluate-rl: ## Run RL agent evaluation
	python evaluation/rl_evaluation.py --episodes 1000
	@echo "📊 RL agent evaluation completed"

evaluate-threats: ## Run threat simulation evaluation
	python evaluation/threat_evaluation.py --all-playbooks
	@echo "📊 Threat simulation evaluation completed"

reproduce-results: ## Reproduce all paper results
	@echo "🔬 Reproducing research results from paper..."
	$(MAKE) evaluate-llm
	$(MAKE) evaluate-rl
	$(MAKE) evaluate-threats
	@echo "✅ Research results reproduction completed"

benchmark: ## Run performance benchmarks
	python evaluation/run_benchmarks.py
	@echo "⚡ Performance benchmarks completed"

# Deployment
docker-build: ## Build Docker images
	docker build -t ai-cyber-lab/llm-analyzer:latest -f docker/llm-analyzer/Dockerfile .
	docker build -t ai-cyber-lab/rl-agent:latest -f docker/rl-agent/Dockerfile .
	docker build -t ai-cyber-lab/threat-simulation:latest -f docker/threat-simulation/Dockerfile .
	@echo "🐳 Docker images built"

k8s-setup: ## Set up Kubernetes cluster (using kind)
	kind create cluster --name cyber-lab --config k8s/kind-config.yaml || echo "Cluster might already exist"
	kubectl apply -f k8s/namespace.yaml
	@echo "☸️  Kubernetes cluster ready"

k8s-deploy: k8s-setup ## Deploy to Kubernetes
	kubectl apply -f k8s/
	@echo "🚀 Deployed to Kubernetes"

k8s-status: ## Check Kubernetes deployment status
	kubectl get pods -n ai-cyber-lab
	kubectl get services -n ai-cyber-lab

k8s-logs: ## View application logs
	kubectl logs -n ai-cyber-lab -l app=llm-analyzer --tail=100

k8s-clean: ## Clean up Kubernetes resources
	kubectl delete namespace ai-cyber-lab || echo "Namespace not found"
	kind delete cluster --name cyber-lab || echo "Cluster not found"

# Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@if [ -d "docs" ]; then \
		cd docs && make html; \
	else \
		echo "docs/ directory not found - documentation generation skipped"; \
	fi

docs-serve: ## Serve documentation locally
	@if [ -d "docs/_build/html" ]; then \
		cd docs/_build/html && python -m http.server 8080; \
	else \
		echo "Documentation not built - run 'make docs' first"; \
	fi

# Research Data
download-datasets: ## Download evaluation datasets
	@echo "📥 Downloading evaluation datasets..."
	mkdir -p datasets
	@echo "Note: Datasets will be available upon paper publication"
	@echo "For now, see evaluation/ directory for data schema and examples"

prepare-datasets: ## Prepare datasets for evaluation
	python scripts/prepare_evaluation_data.py
	@echo "📊 Evaluation datasets prepared"

# Development Utilities
clean: ## Clean up generated files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	@echo "🧹 Cleaned up generated files"

security-scan: ## Run security scans
	bandit -r src/
	safety check
	@echo "🔒 Security scan completed"

pre-commit: ## Run pre-commit hooks
	pre-commit run --all-files
	@echo "✅ Pre-commit checks passed"

# Research Workflow
research-setup: install env-setup k8s-setup ## Complete research environment setup
	@echo "🔬 Research environment setup completed!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Update .env with your OpenAI API key"
	@echo "2. Run 'make reproduce-results' to validate the implementation"
	@echo "3. Explore the codebase and start experimenting!"

validate-implementation: test lint reproduce-results ## Validate complete implementation
	@echo "✅ Implementation validation completed successfully!"
	@echo "🎉 System is ready for research use and paper submission!"

# CI/CD Simulation
ci-pipeline: format lint test-coverage security-scan ## Simulate CI/CD pipeline
	@echo "🔄 CI/CD pipeline simulation completed"

# Quick Start
quick-start: ## Quick start guide
	@echo "🚀 AI-Augmented Cyber Lab - Quick Start"
	@echo "======================================"
	@echo ""
	@echo "1. Environment Setup:"
	@echo "   make research-setup"
	@echo ""
	@echo "2. Validate Implementation:"
	@echo "   make validate-implementation"
	@echo ""
	@echo "3. Reproduce Paper Results:"
	@echo "   make reproduce-results"
	@echo ""
	@echo "4. Deploy System:"
	@echo "   make k8s-deploy"
	@echo ""
	@echo "For detailed instructions, see README.md"

# Version and Info
version: ## Show version information
	@echo "AI-Augmented Cyber Lab v1.0.0"
	@echo "Research reproducibility repository"
	@echo "Paper: AI-Augmented Cyber Labs for Cloud-Native Security Education"
	@python --version
	@kubectl version --client --short 2>/dev/null || echo "kubectl not available"
	@docker --version 2>/dev/null || echo "docker not available"
