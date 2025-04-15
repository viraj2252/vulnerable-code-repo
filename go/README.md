# Vulnerable Go Application

This directory contains a deliberately vulnerable Go application designed to demonstrate common security issues in Go web applications.

## Vulnerabilities

### SQL Injection
- **File**: `src/main.go` (login route)
- **Description**: The application constructs SQL queries using string formatting without parameter binding.
- **Example Attack**: Login with username: `' OR 1=1 --`

### Command Injection
- **File**: `src/main.go` (ping route)
- **Description**: User input is passed directly to exec.Command.
- **Example Attack**: `?host=localhost; cat /etc/passwd`

### Path Traversal
- **File**: `src/main.go` (download route)
- **Description**: File paths are not sanitized, allowing access to files outside the intended directory.
- **Example Attack**: `?filename=../../../etc/passwd`

### Cross-Site Scripting (XSS)
- **File**: `src/main.go` (search route)
- **Description**: User input is directly used in HTML without escaping.
- **Example Attack**: `?q=<script>alert("XSS")</script>`

### Cross-Site Request Forgery (CSRF)
- **File**: `src/main.go` (update-profile route)
- **Description**: No CSRF protection implemented for state-changing operations.
- **Example Attack**: Create a malicious site that submits a form to the vulnerable endpoint.

### Open Redirect
- **File**: `src/main.go` (redirect route)
- **Description**: Redirect URLs are not validated.
- **Example Attack**: `?url=https://malicious-site.com`

### Directory Traversal
- **File**: `src/main.go` (files route)
- **Description**: Directory paths are not sanitized.
- **Example Attack**: `?dir=../../../etc`

### Insecure YAML Parsing
- **File**: `src/main.go` (config route)
- **Description**: Uses potentially unsafe YAML parsing.
- **Example Attack**: Send a YAML document with a payload that executes code.

### Insecure File Upload
- **File**: `src/main.go` (upload route)
- **Description**: No file type or content validation for uploaded files.
- **Example Attack**: Upload a malicious executable file.

### Information Disclosure
- **File**: `src/main.go` (various routes)
- **Description**: Detailed error information is returned to the client.

### Hardcoded Credentials
- **File**: `src/main.go`
- **Description**: Database credentials and session secrets are hardcoded in the source code.

### Security Misconfiguration
- **File**: `src/main.go`
- **Description**: Debug mode enabled and server running on all interfaces without rate limiting.

### Vulnerable Dependencies
- **File**: `go.mod`
- **Description**: The application uses several outdated dependencies with known vulnerabilities.

## Running the Application

1. Ensure you have Go 1.16+ installed

2. Set up a MySQL database named `vulnerable_db`

3. Run the application:
```
cd src
go run main.go
```

4. Access the application at http://localhost:8080

## Warning

This application contains intentional security vulnerabilities and should only be used for testing and educational purposes. Do not use in production or deploy on a public-facing server. 