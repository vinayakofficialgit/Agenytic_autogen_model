# DevSecOps Agentic AI Security Pipeline

An automated security scanning pipeline that combines multiple industry-standard security tools with AI-powered analysis to detect vulnerabilities, secrets, and misconfigurations across your codebase before they reach production.

---

## Overview

This pipeline automatically scans your code repository using five different security tools, analyzes the results using AI, and provides intelligent insights about potential security issues. The system runs on every push and pull request, ensuring continuous security monitoring throughout your development lifecycle.

**Key Capabilities:**
- Automated security scanning with multiple tools
- AI-powered vulnerability analysis and risk assessment
- Automated quality gates to prevent insecure code from merging
- Email notifications with detailed security reports
- Pull request integration with actionable findings

---

## How It Works

The pipeline executes in five sequential stages:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                     TRIGGER: Push or Pull Request                    │
│                                                                       │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                        STAGE 1: Security Scanning                    │
│                                                                       │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│   │   Semgrep    │  │    Trivy     │  │    tfsec     │            │
│   │              │  │              │  │              │            │
│   │ Code Quality │  │  Container   │  │  Terraform   │            │
│   │ & Security   │  │ & Dependency │  │  Security    │            │
│   │   Analysis   │  │  Scanning    │  │   Scanning   │            │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│          │                  │                  │                     │
│          │                  │                  │                     │
│   ┌──────┴──────┐    ┌──────┴──────┐                               │
│   │  Gitleaks   │    │  Conftest   │                               │
│   │             │    │             │                               │
│   │   Secret    │    │   Policy    │                               │
│   │  Detection  │    │ Enforcement │                               │
│   └──────┬──────┘    └──────┬──────┘                               │
│          │                   │                                       │
│          └────────┬──────────┘                                      │
│                   │                                                  │
│                   ▼                                                  │
│          JSON Reports Generated                                     │
│          (saved as artifacts)                                       │
│                                                                      │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                      STAGE 2: AI Analysis                            │
│                                                                       │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │                                                             │   │
│   │  1. Download all scan reports                              │   │
│   │                                                             │   │
│   │  2. Setup Ollama with Llama 3 model                        │   │
│   │                                                             │   │
│   │  3. Analyze findings with AI context                       │   │
│   │     - Categorize by severity                               │   │
│   │     - Identify real threats vs noise                       │   │
│   │     - Generate actionable recommendations                  │   │
│   │                                                             │   │
│   │  4. Create decision.json                                   │   │
│   │     - Overall status (pass/fail)                           │   │
│   │     - Statistics by severity and tool                      │   │
│   │     - Detailed findings list                               │   │
│   │                                                             │   │
│   │  5. Generate pr_comment.md                                 │   │
│   │     - Human-readable summary                               │   │
│   │     - Critical issues highlighted                          │   │
│   │     - Fix recommendations                                  │   │
│   │                                                             │   │
│   └────────────────────────────────────────────────────────────┘   │
│                                                                      │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
┌────────────────────┐  ┌───────────────┐  ┌──────────────────┐
│                    │  │               │  │                  │
│  STAGE 3:          │  │  STAGE 4:     │  │  STAGE 5:        │
│  PR Comment        │  │  Security     │  │  Email           │
│                    │  │  Gate         │  │  Notification    │
│  Posts formatted   │  │               │  │                  │
│  results to        │  │  Blocks merge │  │  Sends detailed  │
│  pull request      │  │  if critical  │  │  report via      │
│  with findings     │  │  issues found │  │  Gmail SMTP      │
│                    │  │               │  │                  │
│  (PRs only)        │  │  ✅ Pass      │  │  Always runs     │
│                    │  │  ❌ Fail      │  │                  │
└────────────────────┘  └───────────────┘  └──────────────────┘
```

---

## Security Tools

### Semgrep - Static Application Security Testing

Semgrep is a fast, lightweight static analysis tool that finds bugs and enforces code standards. It uses pattern matching to detect security vulnerabilities and code quality issues across 30+ programming languages.

**Capabilities:**
- SQL injection vulnerabilities
- Cross-site scripting (XSS) flaws
- Command injection risks
- Authentication and authorization issues
- Insecure cryptographic practices
- Hard-coded credentials
- Race conditions and concurrency bugs
- Memory safety issues
- API misuse patterns

**Why use Semgrep:**
- Language-agnostic with extensive language support
- Fast execution with minimal false positives
- Customizable rules for your specific codebase
- Community-maintained rule registry with thousands of patterns
- Can run locally during development for immediate feedback

---

### Trivy - Container and Dependency Scanner

Trivy scans container images, filesystems, and git repositories for security vulnerabilities in OS packages and application dependencies.

**Capabilities:**
- Docker container images for OS vulnerabilities
- Python packages (pip, pipenv, poetry)
- Node.js dependencies (npm, yarn, pnpm)
- Java libraries (Maven, Gradle)
- Go modules
- Ruby gems
- PHP composer packages
- .NET dependencies
- Operating system packages (Alpine, Debian, Ubuntu, RHEL, etc.)

**Why use Trivy:**
- Comprehensive vulnerability database updated daily
- Detects both known CVEs and security advisories
- Supports offline scanning
- Provides detailed vulnerability information with fix versions
- Minimal configuration required

---

### tfsec - Terraform Security Scanner

tfsec performs static analysis of Terraform code to identify potential security misconfigurations before infrastructure is deployed.

**Capabilities:**
- Encryption settings for data at rest and in transit
- Public exposure of resources (S3 buckets, databases, etc.)
- Overly permissive IAM policies
- Missing security groups and firewall rules
- Insecure network configurations
- Logging and monitoring gaps
- Compliance with AWS, Azure, and GCP best practices

**Why use tfsec:**
- Catches infrastructure security issues before deployment
- Prevents costly misconfigurations in cloud environments
- Built-in checks for major cloud providers
- Clear remediation guidance
- Integrates seamlessly with CI/CD pipelines

---

### Gitleaks - Secret Detection

Gitleaks scans your entire repository history and current code for accidentally committed secrets like passwords, API keys, and tokens.

**Capabilities:**
- AWS access keys and secret keys
- GitHub personal access tokens
- API keys and authentication tokens
- Database connection strings with passwords
- Private SSH keys
- OAuth tokens
- Slack webhooks
- Generic password patterns

**Why use Gitleaks:**
- Prevents credential leaks before they reach version control
- Scans entire git history, not just current files
- Configurable patterns for custom secret formats
- Low false positive rate with smart detection
- Critical for preventing security breaches

---

### Conftest - Policy Enforcement

Conftest tests configuration files against custom policies written in Rego (Open Policy Agent language), ensuring your configurations meet organizational standards.

**Capabilities:**
- Dockerfile best practices and security standards
- Kubernetes manifest compliance
- Terraform configuration policies
- YAML/JSON configuration files
- Custom policy requirements

**Why use Conftest:**
- Enforces company-wide security and compliance standards
- Catches policy violations early in development
- Reusable policies across projects
- Flexible policy language for any configuration format
- Shift-left security with automated enforcement

---


### 4. Enable Workflow

Commit and push the workflow file to your repository. The pipeline will automatically run on subsequent pushes and pull requests to the `main` and `develop` branches.

---

## Pipeline Execution

### Automatic Triggers

The pipeline runs automatically when:

**On Push:**
```bash
git push origin main
git push origin develop
```

**On Pull Request:**
```bash
# When creating or updating PRs targeting main or develop
git push origin feature-branch
# Then create PR via GitHub UI or CLI
```

### What Happens During Execution

**Stage 1 - Security Scanning (5-8 minutes)**
- All five security tools run in parallel
- Each tool generates a JSON report with findings
- Reports are uploaded as downloadable artifacts
- Stage continues even if individual tools encounter errors

**Stage 2 - AI Analysis (2-4 minutes)**
- Downloads all scan reports from Stage 1
- Sets up Ollama with Llama 3 model for local AI processing
- Analyzes findings considering:
  - Severity levels (critical, high, medium, low)
  - Context from surrounding code
  - Likelihood of exploitability
  - Potential business impact
- Generates two key outputs:
  - `decision.json` - Machine-readable decision with statistics
  - `pr_comment.md` - Human-readable markdown summary

**Stage 3 - PR Comment (30 seconds)**
- Only runs for pull requests
- Posts the formatted security report as a PR comment
- Provides immediate feedback to developers

**Stage 4 - Security Gate (30 seconds)**
- Evaluates the AI analysis decision
- Blocks the pipeline if critical or high-severity issues detected
- Prevents merging when configured as a required check

**Stage 5 - Email Notification (30 seconds)**
- Always runs regardless of pass/fail status
- Sends comprehensive email report via Gmail
- Includes vulnerability breakdown and direct links to findings

---

## Output Files

### Scan Reports (Stage 1 Output)

Located in the `reports/` directory:

```
reports/
├── semgrep.json              # SAST findings from Semgrep
├── trivy.json                # Filesystem scan results
├── trivy-image.json          # Docker image vulnerabilities
├── tfsec.json                # Terraform security issues
├── gitleaks.json             # Detected secrets
├── conftest-dockerfile.json  # Dockerfile policy results
├── conftest-k8s.json         # Kubernetes policy results
└── conftest-terraform.json   # Terraform policy results
```

### AI Analysis Output (Stage 2 Output)

Located in the `agent_output/` directory:

**decision.json** - Complete analysis with statistics:


**pr_comment.md** - Formatted summary for developers:
```markdown
## 🛡️ Security Scan Results

**Status:** ❌ FAILED

### Summary
Detected **12 security issues** that require attention:
- 🔴 Critical: 2
- 🟠 High: 4
- 🟡 Medium: 5
- 🟢 Low: 1

### Critical Issues Requiring Immediate Action

#### 1. AWS Access Key Detected
**Tool:** Gitleaks  
**File:** `src/config.py:27`  
**Issue:** Hardcoded AWS credentials found in source code  
**Fix:** Move credentials to environment variables or AWS Secrets Manager

#### 2. SQL Injection Vulnerability
**Tool:** Semgrep  
**File:** `src/database.py:145`  
**Issue:** User input concatenated directly into SQL query  
**Fix:** Use parameterized queries or ORM methods to prevent SQL injection

### High Severity Issues

[Additional findings listed here with details]

---

**Action Required:** Critical vulnerabilities must be resolved before this PR can be merged.
```

---

## Email Notifications

The pipeline uses Gmail as the notification service to deliver security reports directly to your team's inbox.

### Email Content

**Subject Line:**
- Failed scan: `🔴 [SECURITY ALERT] username/repository - branch-name`
- Passed scan: `🟢 [SECURITY OK] username/repository - branch-name`

**Email Body Contains:**
- Pass/fail status with visual indicators
- Repository, branch, and commit information
- GitHub username of the person who triggered the scan
- Total number of findings
- Breakdown by severity (critical, high, medium, low)
- Reason for the pass/fail decision
- Direct links to GitHub Actions workflow run and specific commit
- Action required message for failures

**Priority Setting:**
- High priority for failed scans
- Normal priority for passed scans

---

## Understanding the Results

### Pass/Fail Logic

The pipeline fails when:
- Any critical severity vulnerabilities are detected
- High severity vulnerabilities exceed acceptable thresholds
- Secrets or credentials are found in code
- Infrastructure misconfigurations pose immediate security risks

The pipeline passes when:
- No critical or high-severity issues are found
- Only medium or low severity issues present
- All findings are within acceptable risk tolerance

### Severity Levels

**Critical** - Immediate security risk requiring urgent action
- Exposed credentials, API keys, passwords
- Remote code execution vulnerabilities
- Authentication bypasses
- Data exposure to public internet

**High** - Significant security risk requiring prompt attention
- SQL injection vulnerabilities
- Cross-site scripting (XSS) flaws
- Insecure cryptographic implementations
- Missing security controls

**Medium** - Moderate security concern
- Outdated dependencies with known vulnerabilities
- Weak configuration settings
- Missing security headers
- Information disclosure issues

**Low** - Minor security improvements
- Code quality issues with security implications
- Best practice violations
- Informational findings

---

## Viewing Results

### In GitHub Actions

1. Navigate to the **Actions** tab in your repository
2. Click on the latest workflow run
3. View the **Job Summary** for high-level results
4. Download artifacts to see detailed JSON reports

### In Pull Requests

When the pipeline runs on a pull request:
- A comment is automatically posted with scan results
- The security gate check appears in the PR status checks
- PR cannot be merged if critical issues are found (when gate is configured as required)

### In Email

Security reports are delivered to the configured notification email address immediately after each scan completes, providing instant visibility to your security team.

---

## Configuration Options

### Environment Variables

You can modify these variables in the workflow file's `env:` section:

| Variable | Description | Default |
|----------|-------------|---------|
| `PYTHON_VERSION` | Python version for AI analysis | `3.12` |
| `REPORTS_DIR` | Directory for scan reports | `reports` |
| `OUTPUT_DIR` | Directory for AI analysis output | `agent_output` |
| `LLM_ENABLED` | Enable/disable AI model (1 or 0) | `1` |
| `OLLAMA_MODEL` | AI model to use | `llama3:latest` |
| `MIN_SEVERITY` | Minimum severity to report | `high` |

### Trigger Configuration

Current configuration runs on:
- Pushes to `main` and `develop` branches
- Pull requests targeting `main` and `develop` branches

Commented optional triggers available:
- Scheduled runs (e.g., weekly scans)
- Manual workflow dispatch

---

## Architecture Details

### Why Five Different Tools?

Each security tool specializes in a specific area of vulnerability detection. Using multiple tools provides comprehensive coverage:

**Semgrep** excels at finding code-level vulnerabilities and enforcing coding standards through pattern matching.

**Trivy** specializes in scanning dependencies and containers, catching known CVEs in third-party libraries and base images.

**tfsec** focuses exclusively on infrastructure-as-code, preventing cloud misconfigurations before deployment.

**Gitleaks** is purpose-built for secret detection, using specialized algorithms to find credentials others might miss.

**Conftest** enables custom policy enforcement, ensuring your specific organizational requirements are met.

### AI Analysis Benefits

The AI analysis layer processes findings from all five tools and provides:

**Contextual Understanding** - Considers the surrounding code and application context when evaluating severity, not just the raw tool output.

**Intelligent Prioritization** - Ranks issues based on actual exploitability and business impact, helping teams focus on real risks.

**Noise Reduction** - Filters out irrelevant findings that would otherwise waste developer time.

**Actionable Guidance** - Generates specific, practical recommendations for fixing each issue rather than generic advice.

**Consistent Decisions** - Applies the same evaluation criteria across all scans for predictable, reliable quality gates.

### Artifact Storage

All scan reports and analysis results are stored as GitHub Actions artifacts with 30-day retention, allowing:
- Historical comparison of security posture
- Audit trail for compliance requirements
- Detailed investigation of specific findings
- Offline analysis and reporting

---


### Scanner Installation Failures

Installation steps include fallback mechanisms and will generate empty reports if a tool fails to install. Check the workflow logs for specific error messages. Most tools will continue the workflow even if they fail, ensuring partial results are still available.

### Ollama Timeout

The AI model setup step has a 10-minute timeout and is configured to continue even if it fails. The analysis can still complete using the Python script logic without the LLM enhancement.

### Missing Artifacts

Ensure the `reports/` and `agent_output/` directories are being created and populated by checking the workflow step outputs. Verify that the upload artifact steps are executing successfully in the GitHub Actions logs.

### PR Comment Not Appearing

Verify that the workflow has the necessary permissions to write to pull requests. Check the repository settings to ensure the `GITHUB_TOKEN` has `pull-requests: write` permission enabled.

---

This pipeline provides automated, comprehensive security scanning with intelligent analysis, helping your team catch vulnerabilities early and maintain a strong security posture throughout the development lifecycle.