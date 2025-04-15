# Vulnerable Python Application

This directory contains a deliberately vulnerable Flask application designed to demonstrate common security issues in Python web applications.

## Vulnerabilities

### SQL Injection
- **File**: `src/app.py` (login route)
- **Description**: The application uses string interpolation to construct SQL queries, allowing attackers to inject malicious SQL.
- **Example Attack**: Username: `' OR 1=1 --`

### Cross-Site Scripting (XSS)
- **File**: `src/app.py` (search route)
- **Description**: User input is directly rendered in HTML templates without escaping.
- **Example Attack**: `/?q=<script>alert("XSS")</script>`

### Command Injection
- **File**: `src/app.py` (ping route)
- **Description**: User input is passed directly to shell commands.
- **Example Attack**: `hostname=; cat /etc/passwd`

### Insecure Deserialization
- **File**: `src/app.py` (object_page route)
- **Description**: The application deserializes untrusted data using pickle.
- **Example Attack**: Send a crafted pickle object to execute arbitrary code.

### Path Traversal
- **File**: `src/app.py` (download_file route)
- **Description**: File paths are not sanitized, allowing access to files outside the intended directory.
- **Example Attack**: `?filename=../../../etc/passwd`

### Insecure YAML Parsing
- **File**: `src/app.py` (parse_config route)
- **Description**: Using yaml.load with unsafe Loader enables code execution.
- **Example Attack**: Submit a YAML document with a payload that executes code.

### Vulnerable Dependencies
- **File**: `requirements.txt`
- **Description**: The application uses several outdated packages with known vulnerabilities.

### Hardcoded Credentials
- **File**: `src/app.py`
- **Description**: Database credentials and secret keys are hardcoded in the source code.

### Security Misconfiguration
- **File**: `src/app.py`
- **Description**: Application runs in debug mode and binds to all interfaces.

## Running the Application

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Run the application:
```
python src/app.py
```

3. Access the application at http://localhost:5000

## Warning

This application contains intentional security vulnerabilities and should only be used for testing and educational purposes. Do not use in production or deploy on a public-facing server. 