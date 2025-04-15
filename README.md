# Vulnerable Code Repository

This repository contains deliberately vulnerable code examples across multiple programming languages for evaluating security scanning tools.

## Purpose

The primary goal of this repository is to provide a comprehensive test bed for:
- Assessing the effectiveness of security scanning tools
- Comparing the detection capabilities of different tools
- Training security professionals in identifying vulnerabilities

## Languages and Frameworks

This repository includes vulnerable code in:
- Java
- Python
- JavaScript (Node.js)
- C#
- Go
- F# 
- Terraform (IaC)

## Vulnerability Categories

The repository contains examples of the following vulnerability types:

| Category | Vulnerabilities |
|----------|----------------|
| Injection | SQL Injection, Command Injection, LDAP Injection |
| Cross-Site Scripting (XSS) | Reflected XSS, Stored XSS, DOM-based XSS |
| Authentication | Weak Password Storage, Session Fixation |
| Authorization | Insecure Direct Object References, Missing Function Level Access Control |
| Sensitive Data | Hardcoded Credentials, Insecure Cryptographic Storage |
| Security Misconfiguration | Default Configurations, Verbose Error Messages |
| Broken Access Control | Path Traversal, IDOR, Permission Issues |
| Cryptographic Failures | Weak Algorithms, Hardcoded Keys, Improper Certificate Validation |
| Insecure Design | Missing Security Controls, Insecure Default Settings |
| Vulnerable Dependencies | Outdated Libraries, Vulnerable Framework Versions |
| Infrastructure Vulnerabilities | Insecure Cloud Configurations, Overly Permissive Access |
| Server-Side Request Forgery | Unvalidated URL access, Open Redirects |
| Software & Data Integrity Failures | Insecure Deserialization, YAML/XML Parsing Issues |

## Repository Structure

```
vulnerable-project/
├── java/
├── python/
├── javascript/
├── csharp/
├── go/
├── fsharp/
├── terraform/
└── docs/
```

## OWASP Top 10 Coverage

This repository covers all OWASP Top 10 (2021) vulnerability categories:

1. **A01:2021 - Broken Access Control**: IDOR, path traversal, missing access controls
2. **A02:2021 - Cryptographic Failures**: Weak encryption, hardcoded keys, plaintext storage
3. **A03:2021 - Injection**: SQL injection, command injection, XSS
4. **A04:2021 - Insecure Design**: Insecure defaults, missing security controls
5. **A05:2021 - Security Misconfiguration**: Debug settings, default configs, verbose errors
6. **A06:2021 - Vulnerable and Outdated Components**: Outdated libraries across all projects
7. **A07:2021 - Identification and Authentication Failures**: Weak passwords, insecure tokens
8. **A08:2021 - Software and Data Integrity Failures**: Insecure deserialization, unsafe parsing
9. **A09:2021 - Security Logging and Monitoring Failures**: Missing or insufficient logging
10. **A10:2021 - Server-Side Request Forgery**: Unsafe URL loading, open redirects

## Usage Instructions

1. Clone this repository
2. Run the specific language examples according to their README files
3. Use various security scanning tools against this codebase
4. Compare results to the known vulnerabilities documented in each section

## Warning

**DO NOT USE THIS CODE IN PRODUCTION ENVIRONMENTS**

The code in this repository is deliberately vulnerable and is intended for educational and testing purposes only.

## Contribution

Feel free to contribute additional vulnerability examples by submitting a pull request. 