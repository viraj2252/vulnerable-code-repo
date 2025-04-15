# Vulnerable F# Application

**WARNING: THIS PROJECT CONTAINS DELIBERATE SECURITY VULNERABILITIES FOR EDUCATIONAL PURPOSES ONLY**

This project demonstrates a collection of common security vulnerabilities and bad practices in F#. It is designed for educational purposes to help developers learn about security vulnerabilities and how to avoid them.

## Purpose

This deliberately vulnerable application demonstrates various security flaws that could occur in F# applications. The code should **NEVER** be used in a production environment.

## Vulnerabilities Included

### Data Model Vulnerabilities
- Plain text storage of sensitive data (passwords, SSNs, credit card numbers)
- Excessive data exposure
- Insecure serialization
- Missing validation attributes
- No CSRF protection

### Database Access Vulnerabilities
- SQL injection through string concatenation/interpolation
- Hardcoded credentials
- Excessive privilege use
- Connection pooling issues
- Unsafe raw query execution

### API and Web Vulnerabilities
- No access control or authorization
- XML External Entity (XXE) vulnerabilities
- Server-Side Request Forgery (SSRF)
- Insecure file uploads
- Path traversal
- Insecure deserialization
- Command injection
- Open redirect
- Insecure Direct Object References (IDOR)
- Error details exposure
- No rate limiting

### Cryptographic Vulnerabilities
- Weak encryption algorithms (DES)
- Insecure AES modes (ECB)
- Static/hardcoded keys and IVs
- Weak hashing algorithms (MD5, SHA1)
- Insecure password storage (no salt, weak hashing)
- Timing attack vulnerabilities
- Broken HMAC implementation
- Weak RNG
- Small RSA key sizes

### General Implementation Issues
- Hardcoded secrets
- Insecure initialization
- Command-line vulnerabilities
- Excessive logging of sensitive information
- Verbose error messages

## Structure

The code is organized into the following files:

- `Models.fs` - Vulnerable data models
- `Database.fs` - Insecure database access
- `Api.fs` - Vulnerable web endpoints
- `Encryption.fs` - Weak cryptographic implementations
- `Program.fs` - Main entry point with vulnerable initialization

## Usage

**DO NOT USE THIS CODE IN PRODUCTION**

This project is intended to be used solely for educational purposes, such as:
- Learning about security vulnerabilities in F# applications
- Security training
- Security testing practice

## Build and Run

```
dotnet build
dotnet run
```

By default, the application will start a web server on port 8080.

## Secure Alternatives

For each vulnerability, here are recommended secure alternatives:

1. **Data Protection**:
   - Use data protection libraries
   - Hash passwords with strong algorithms (Argon2, bcrypt)
   - Encrypt sensitive data
   - Implement proper input validation

2. **SQL Safety**:
   - Use parameterized queries
   - Implement proper connection pooling
   - Use principle of least privilege
   - Store connection strings securely

3. **Web Security**:
   - Implement proper authentication and authorization
   - Apply CSRF protection
   - Validate and sanitize all inputs
   - Implement proper file upload validation
   - Add rate limiting

4. **Cryptography**:
   - Use strong encryption algorithms (AES-256)
   - Implement proper key management
   - Use secure modes of operation (CBC with proper IV, GCM)
   - Use strong hashing algorithms (SHA-256, SHA-3)
   - Use cryptographically secure random number generators
   - Implement secure key sizes for asymmetric crypto

## License

This code is for educational purposes only. It should never be used in a production environment. 