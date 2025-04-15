# Vulnerability Reference Guide

This document provides an overview of the common vulnerabilities demonstrated in this repository.

## Injection Vulnerabilities

### SQL Injection
- **Description**: Occurs when untrusted data is sent to an interpreter as part of a command or query.
- **Impact**: Unauthorized data access, data manipulation, or execution of admin commands.
- **Examples in Repository**:
  - Python: String interpolation in SQL queries
  - Java: Direct string concatenation in SQL queries
  - JavaScript: Unsanitized MongoDB queries
  - C#: String concatenation in SQL queries
  - Go: String formatting in SQL queries

### Command Injection
- **Description**: Occurs when untrusted data is sent to a system shell.
- **Impact**: Execution of arbitrary commands on the host operating system.
- **Examples in Repository**:
  - Python: Using untrusted input in subprocess calls
  - Java: Passing untrusted input to Runtime.exec()
  - JavaScript: Passing user input to exec()
  - C#: Using untrusted input in Process.Start()
  - Go: Using user input in exec.Command()

### XML External Entity (XXE) Injection
- **Description**: Occurs when XML parsers process external entity references in XML documents.
- **Impact**: Disclosure of internal files, SSRF, denial of service.
- **Examples in Repository**:
  - Java: Insecure XML parsing configuration
  - C#: XML parsing with external entity resolution enabled

## Cross-Site Scripting (XSS)

- **Description**: Occurs when an application includes untrusted data in a web page without proper validation or escaping.
- **Impact**: Session hijacking, credential theft, phishing attacks.
- **Types**:
  - Reflected XSS: Non-persistent, reflected back in the immediate response
  - Stored XSS: Persistently stored and later displayed to users
  - DOM-based XSS: Vulnerability in client-side JavaScript
- **Examples in Repository**:
  - Python: Unescaped user input in HTML templates
  - JavaScript: Inserting user input directly into HTML
  - Java: Unsanitized user data in JSPs
  - C#: User data directly rendered in HTML
  - Go: Unescaped user input in HTML responses

## Authentication and Authorization Weaknesses

### Weak Password Storage
- **Description**: Storing passwords in plaintext or using weak hashing algorithms.
- **Impact**: Password theft if database is compromised.
- **Examples in Repository**:
  - Python: Storing passwords in plaintext
  - Java: No password hashing in User model
  - JavaScript: Plaintext password storage

### Insecure Direct Object References (IDOR)
- **Description**: Exposing a reference to an internal implementation object without access control.
- **Impact**: Unauthorized access to data or functionality.
- **Examples in Repository**:
  - Python: No access control on user data access
  - Java: No authentication checks for data retrieval
  - Go: Missing authorization for user profile access
  - C#: No authorization check for user data access

### Missing Function Level Access Control
- **Description**: Failure to restrict access to sensitive functionality at the server level.
- **Impact**: Unauthorized access to administrative functions.
- **Examples in Repository**:
  - Various admin endpoints without proper authorization

## Sensitive Data Exposure

### Hardcoded Credentials
- **Description**: Embedding credentials directly in source code.
- **Impact**: Credential compromise if source code is exposed.
- **Examples in Repository**:
  - Python: Hardcoded database credentials
  - Java: Hardcoded connection strings
  - JavaScript: Hardcoded API keys
  - Go: Hardcoded database credentials
  - C#: Hardcoded connection strings

### Insecure Cryptographic Storage
- **Description**: Using weak cryptographic algorithms or improper key management.
- **Impact**: Decryption of sensitive data.
- **Examples in Repository**:
  - Java: Weak encryption algorithms
  - Python: Insecure random number generation

### Information Disclosure in Errors
- **Description**: Revealing sensitive information in error messages.
- **Impact**: Information leakage that aids attackers.
- **Examples in Repository**:
  - JavaScript: Detailed error responses
  - C#: Exception details sent to client
  - Go: Detailed error messages

## Security Misconfiguration

### Default Configurations
- **Description**: Using insecure default settings for frameworks and libraries.
- **Impact**: Various security weaknesses.
- **Examples in Repository**:
  - Python: Debug mode enabled in production
  - Java: Default CORS settings
  - C#: Development error pages in production

### Cross-Origin Resource Sharing (CORS) Misconfiguration
- **Description**: Overly permissive CORS policies.
- **Impact**: Allows malicious sites to make cross-origin requests.
- **Examples in Repository**:
  - C#: Allowing all origins, methods, and headers
  - JavaScript: Insecure CORS configuration

## Deserialization Vulnerabilities

### Insecure Deserialization
- **Description**: Processing untrusted serialized data without validation.
- **Impact**: Remote code execution, injection attacks.
- **Examples in Repository**:
  - Python: Unsafe pickle deserialization
  - Java: Insecure ObjectInputStream usage
  - JavaScript: Unsafe eval of JSON
  - C#: Using TypeNameHandling.All in JSON deserialization

### YAML Parsing Vulnerabilities
- **Description**: YAML parsers that allow code execution.
- **Impact**: Remote code execution.
- **Examples in Repository**:
  - Python: Unsafe yaml.load()
  - Go: Unsafe YAML parsing
  - C#: YAML deserialization without validation

## File-Related Vulnerabilities

### Path Traversal
- **Description**: Improper validation of file paths.
- **Impact**: Access to files outside intended directory.
- **Examples in Repository**:
  - Python: Unsanitized file access
  - Java: Direct file path manipulation
  - JavaScript: Unsanitized file path handling
  - C#: User-controlled file paths
  - Go: Unsanitized file access

### Unrestricted File Upload
- **Description**: Allowing upload of dangerous file types.
- **Impact**: Remote code execution, XSS, content spoofing.
- **Examples in Repository**:
  - JavaScript: No file type validation
  - Java: Missing file content checks
  - Go: No validation of uploaded files

## Dependency Issues

### Vulnerable Dependencies
- **Description**: Using libraries or frameworks with known vulnerabilities.
- **Impact**: Varies based on the specific vulnerability.
- **Examples in Repository**:
  - Python: Outdated packages like flask 2.0.1
  - Java: Vulnerable Log4j version
  - JavaScript: Outdated npm packages
  - C#: Outdated NuGet packages
  - Go: Vulnerable dependencies

## Network Security

### Open Redirect
- **Description**: Redirect to arbitrary URL without validation.
- **Impact**: Phishing, malware distribution.
- **Examples in Repository**:
  - Go: Unvalidated URL redirects
  - C#: No validation of redirect URLs

### No Rate Limiting
- **Description**: Missing protection against brute force attacks.
- **Impact**: Account takeover, denial of service.
- **Examples in Repository**:
  - Various login endpoints without rate limiting

## Testing for Vulnerabilities

### SQL Injection Testing
1. Try entering `' OR 1=1 --` in login forms
2. Use SQL metacharacters (`'`, `"`, `#`, `;`, etc.) in input fields
3. Look for error messages that reveal SQL syntax

### XSS Testing
1. Try entering `<script>alert('XSS')</script>` in input fields
2. Test variations like `<img src="x" onerror="alert('XSS')">` to bypass filters
3. Check if input is reflected without proper encoding

### Path Traversal Testing
1. Try accessing files with `../../../etc/passwd` (Linux) or `../../../Windows/win.ini` (Windows)
2. Test URL-encoded versions like `%2e%2e%2f%2e%2e%2f`
3. Try absolute paths to critical files

### Command Injection Testing
1. Try appending commands with operators like `& ls -la` or `; cat /etc/passwd`
2. Use backticks or $(command) syntax for command substitution
3. Look for delayed responses that indicate command execution

## Best Practices for Remediation

### Preventing Injection
- Use parameterized queries or prepared statements
- Validate and sanitize all user inputs
- Use ORM frameworks with safe query building

### Securing Authentication
- Use strong password hashing algorithms (bcrypt, Argon2)
- Implement multi-factor authentication
- Use secure session management

### Protecting Sensitive Data
- Encrypt sensitive data at rest and in transit
- Use environment variables for configuration
- Implement proper key management

### Implementing Access Control
- Enforce least privilege principle
- Check authorization for each function
- Use role-based access control

### Secure Dependency Management
- Regularly update dependencies
- Use dependency scanning tools
- Remove unused dependencies

## Conclusion

This repository demonstrates various security vulnerabilities for educational purposes. Remember that exploiting these vulnerabilities in real-world systems without permission is illegal and unethical. 