# Security Policy

## Supported Versions

We actively maintain security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The AI-Augmented Cyber Lab project takes security seriously. We appreciate your efforts to responsibly disclose any security vulnerabilities.

### Reporting Process

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing **akshay.mittal@ieee.org** with the following information:

1. **Description**: A clear description of the vulnerability
2. **Impact**: Potential impact and severity assessment
3. **Reproduction**: Steps to reproduce the vulnerability
4. **Environment**: Affected versions and configurations
5. **Mitigation**: Any temporary workarounds you've identified

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Status Updates**: Every 7 days until resolution
- **Resolution**: Coordinated disclosure timeline (typically 90 days)

### Security Measures

This project implements several security measures:

#### Code Security
- **Dependency Scanning**: Regular vulnerability scans of dependencies
- **Static Analysis**: Automated code security analysis
- **Input Validation**: Comprehensive validation of all user inputs
- **Authentication**: Secure JWT-based authentication system

#### Infrastructure Security
- **Container Security**: Non-root containers with minimal attack surface
- **Network Policies**: Kubernetes network segmentation
- **RBAC**: Least-privilege access controls
- **Secret Management**: Secure handling of API keys and credentials

#### Educational Content Security
- **Sandboxed Environments**: Isolated simulation environments
- **Safe Playbooks**: Validated attack scenarios with safety controls
- **Access Controls**: Student workspace isolation
- **Audit Logging**: Comprehensive activity logging

## Security Best Practices for Users

### API Key Security
```bash
# ✅ DO: Use environment variables
OPENAI_API_KEY=your-api-key

# ❌ DON'T: Hardcode in source files
openai_key = "sk-..."  # Never do this
```

### Kubernetes Security
```yaml
# ✅ DO: Use security contexts
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true

# ❌ DON'T: Use privileged containers
securityContext:
  privileged: true  # Avoid this
```

### Development Security
- Always use virtual environments
- Keep dependencies updated
- Never commit secrets to version control
- Use secure coding practices for extensions

## Known Security Considerations

### Educational Context
This system is designed for educational purposes and includes:
- **Simulated Vulnerabilities**: Intentionally vulnerable examples for learning
- **Attack Scenarios**: Controlled threat simulation environments
- **Security Playbooks**: Educational attack techniques

These components are designed with safety controls and should only be used in isolated educational environments.

### Production Deployment
For production educational deployments:
- Use network segmentation
- Implement monitoring and alerting
- Regular security updates
- Access logging and audit trails
- Student data privacy protection

## Vulnerability Disclosure History

Currently, no security vulnerabilities have been reported or disclosed.

## Security Research

We welcome security research on this educational platform. If you're conducting security research:

1. **Scope**: Focus on the platform itself, not the educational vulnerabilities
2. **Ethics**: Follow responsible disclosure principles
3. **Attribution**: We're happy to acknowledge security researchers
4. **Coordination**: Work with us on responsible timeline for fixes

## Contact

For security-related questions:
- **Email**: akshay.mittal@ieee.org
- **Subject**: [SECURITY] Your security topic
- **Response Time**: Within 48 hours

For general questions, please use GitHub issues (non-security only).

---

**Note**: This security policy applies to the AI-Augmented Cyber Lab platform infrastructure. The educational content includes intentional vulnerabilities for learning purposes, which are documented in the research paper and README.
