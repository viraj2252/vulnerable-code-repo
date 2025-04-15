# Vulnerable JavaScript/Node.js Application

This directory contains a deliberately vulnerable Node.js application designed to demonstrate common security issues in JavaScript web applications.

## Vulnerabilities

### NoSQL Injection
- **File**: `src/server.js` (login route)
- **Description**: The application uses direct query parameters without sanitization, allowing NoSQL injection attacks.
- **Example Attack**: Send a JSON body with `{"username": {"$ne": null}, "password": {"$ne": null}}` to bypass authentication.

### Command Injection
- **File**: `src/server.js` (ping route)
- **Description**: User input is passed directly to shell commands.
- **Example Attack**: `?host=localhost; cat /etc/passwd`

### Path Traversal
- **File**: `src/server.js` (read-file route)
- **Description**: File paths are not sanitized, allowing access to files outside the intended directory.
- **Example Attack**: `?filename=../../../etc/passwd`

### Server-Side Template Injection
- **File**: `src/server.js` (template route)
- **Description**: User input is directly used in template rendering.
- **Example Attack**: `?name=<%= process.env.SECRET_KEY %>`

### Insecure Direct Object Reference
- **File**: `src/server.js` (users route)
- **Description**: User records can be accessed by ID without proper authorization checks.
- **Example Attack**: Access `/api/users/123` without authentication.

### Unrestricted File Upload
- **File**: `src/server.js` (upload route)
- **Description**: The application allows uploading of any file type without validation.
- **Example Attack**: Upload a malicious PHP script.

### Information Disclosure
- **File**: `src/server.js` (error handler)
- **Description**: Detailed error information including stack traces is sent to the client.

### Plaintext Password Storage
- **File**: `src/server.js` (user schema)
- **Description**: User passwords are stored in plaintext rather than being hashed.

### Hardcoded Secrets
- **File**: `src/server.js`
- **Description**: JWT secret key is hardcoded in the source code.

### Vulnerable Dependencies
- **File**: `package.json`
- **Description**: The application uses several outdated packages with known vulnerabilities.

## Running the Application

1. Install MongoDB (required for the application)

2. Install dependencies:
```
npm install
```

3. Run the application:
```
npm start
```

4. Access the application at http://localhost:3000

## Warning

This application contains intentional security vulnerabilities and should only be used for testing and educational purposes. Do not use in production or deploy on a public-facing server. 