# Contributing to AI-Augmented Cyber Lab

We welcome contributions from the research community! This project aims to advance cybersecurity education through AI-driven approaches.

## 🎯 Research Contribution Areas

### High Priority
- **Evaluation Datasets**: Contribute additional cloud-native security artifacts with ground truth annotations
- **Attack Playbooks**: Add new MITRE ATT&CK aligned attack scenarios
- **Educational Content**: Develop learning modules for emerging cloud security topics
- **Model Improvements**: Enhance LLM prompt engineering for higher accuracy

### Medium Priority
- **Integration**: Connect with existing cybersecurity training platforms
- **Visualization**: Improve learning analytics and progress tracking
- **Performance**: Optimize RL agent training and hint delivery
- **Documentation**: Expand setup guides and troubleshooting

## 🔬 Research Standards

### Code Quality
- Follow PEP 8 for Python code
- Include comprehensive docstrings and type hints
- Maintain >80% test coverage for new features
- Use Black for code formatting

### Research Rigor
- Provide empirical validation for new features
- Include statistical significance testing where appropriate
- Document methodology and experimental setup
- Cite relevant literature and related work

### Security Best Practices
- Never commit API keys or secrets
- Follow secure coding practices for educational content
- Validate all user inputs and artifacts
- Implement proper access controls

## 📋 Contribution Process

### 1. Research Proposal
For significant research contributions:
1. Open an issue describing your research idea
2. Include methodology, expected outcomes, and evaluation plan
3. Discuss with maintainers before implementation
4. Reference relevant literature and novelty claims

### 2. Development Workflow
```bash
# Fork the repository
git clone https://github.com/your-username/AI-Augmented-Cyber-Lab.git
cd AI-Augmented-Cyber-Lab

# Create feature branch
git checkout -b feature/your-research-contribution

# Set up development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Make your changes
# ... implement your contribution ...

# Run tests
pytest tests/
python -m pytest tests/ --cov=src/

# Run evaluation to ensure no regression
python evaluation/run_llm_evaluation.py
python evaluation/run_rl_evaluation.py

# Format code
black src/ tests/
flake8 src/ tests/

# Commit and push
git add .
git commit -m "Add: [brief description of research contribution]"
git push origin feature/your-research-contribution
```

### 3. Pull Request Guidelines
**Title Format**: `[RESEARCH|FEATURE|FIX]: Brief description`

**Required Information**:
- **Research Motivation**: Why is this contribution valuable?
- **Methodology**: How did you implement/evaluate the changes?
- **Results**: What improvements or insights were achieved?
- **Testing**: How did you validate the contribution?
- **Breaking Changes**: Any API or configuration changes?

**Template**:
```markdown
## Research Contribution Summary
Brief description of the contribution and its significance.

## Methodology
- Approach taken
- Evaluation criteria
- Experimental setup

## Results
- Performance improvements (with numbers)
- Statistical significance (if applicable)
- Comparison with baseline

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Evaluation benchmarks maintained
- [ ] Documentation updated

## Related Work
References to relevant papers or existing solutions.
```

## 🧪 Evaluation and Testing

### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# End-to-end evaluation
python evaluation/run_comprehensive_evaluation.py

# Performance benchmarks
python evaluation/run_benchmarks.py
```

### Adding New Tests
- Unit tests for all new functions/classes
- Integration tests for component interactions
- Evaluation scripts for research claims
- Performance regression tests

## 📊 Research Data and Datasets

### Contributing Evaluation Data
1. **Format**: Follow existing dataset schema in `datasets/schema.json`
2. **Quality**: Ensure expert validation of ground truth annotations  
3. **Diversity**: Include various artifact types and vulnerability categories
4. **Ethics**: Ensure all data is publicly available or appropriately licensed
5. **Documentation**: Provide clear methodology for data collection/annotation

### Dataset Structure
```
datasets/
├── evaluation_corpus_1500.json     # Main evaluation dataset
├── training_examples.json          # Few-shot training examples
├── attack_scenarios/               # Threat simulation scenarios
└── student_interaction_logs/       # Anonymized learning data
```

## 🤝 Community Guidelines

### Communication
- Be respectful and constructive in discussions
- Focus on research merit and educational value
- Acknowledge prior work and contributions
- Share knowledge and help other researchers

### Research Ethics
- Ensure responsible disclosure of security vulnerabilities
- Respect privacy in educational data collection
- Follow institutional IRB guidelines for human subjects
- Maintain scientific integrity in evaluation and reporting

## 🏆 Recognition

### Contributor Types
- **Research Contributors**: Novel algorithms, evaluation methods, or insights
- **Data Contributors**: High-quality datasets and annotations
- **Code Contributors**: Implementation improvements and bug fixes
- **Documentation Contributors**: Guides, tutorials, and examples

### Citation Guidelines
Please cite the original paper when using this codebase:
```bibtex
@inproceedings{ai-augmented-cyber-lab-2024,
  title={AI-Augmented Cyber Labs: Enhancing Cloud-Native Security Education through Adaptive Feedback and Threat Simulation},
  author={[Authors]},
  booktitle={Proceedings of the ACM Conference on Computer Science Education},
  year={2024},
  publisher={ACM}
}
```

## 🐛 Bug Reports and Issues

### Bug Report Template
```markdown
**Description**: Clear description of the issue
**Steps to Reproduce**: Numbered steps to reproduce the behavior
**Expected Behavior**: What you expected to happen
**Actual Behavior**: What actually happened
**Environment**: 
- OS: [e.g. Ubuntu 22.04]
- Python version: [e.g. 3.9.7]
- Dependencies: [relevant package versions]
**Additional Context**: Screenshots, logs, or other relevant information
```

### Security Issues
For security vulnerabilities, please email akshay.mittal@ieee.org directly instead of opening a public issue.

## 📚 Research Resources

### Recommended Reading
- MITRE ATT&CK Framework documentation
- Kubernetes security best practices
- Educational technology research methods
- Reinforcement learning in education literature

### Development Tools
- **IDE**: VS Code with Python extensions
- **Testing**: pytest, coverage.py
- **Formatting**: black, flake8, mypy
- **Documentation**: Sphinx, MkDocs
- **Containers**: Docker, kind (for Kubernetes testing)

## 🎉 Getting Started

1. **Read the Paper**: Understand the research contribution and methodology
2. **Try the System**: Follow the README to set up and test the system
3. **Explore the Code**: Understand the architecture and implementation
4. **Join Discussions**: Participate in GitHub issues and discussions
5. **Start Contributing**: Begin with documentation or small improvements

## 📞 Contact

- **Technical Questions**: Open a GitHub issue
- **Research Collaboration**: Email akshay.mittal@ieee.org
- **General Discussion**: Use GitHub Discussions

Thank you for contributing to advancing cybersecurity education research! 🚀
