# Vulnerable Java Application

This directory contains a deliberately vulnerable Java application designed to demonstrate common security issues in Java web applications.

## Vulnerabilities

### SQL Injection
- **File**: `src/main/java/com/example/controller/UserController.java` (searchUsers and authenticateUser methods)
- **Description**: The application constructs SQL queries using string concatenation.
- **Example Attack**: Username: `' OR 1=1 --` in login or search forms

### Cross-Site Scripting (XSS)
- **File**: `src/main/java/com/example/controller/UserController.java` (userProfile method)
- **Description**: User input is directly displayed in the view without proper escaping.
- **Example Attack**: Name parameter with `<script>alert("XSS")</script>`

### Path Traversal
- **File**: `src/main/java/com/example/controller/UserController.java` (downloadFile method)
- **Description**: User-provided filename is used directly to access files.
- **Example Attack**: `?filename=../../../etc/passwd`

### Command Injection
- **File**: `src/main/java/com/example/controller/UserController.java` (pingHost method)
- **Description**: User input is passed directly to system commands.
- **Example Attack**: `?host=localhost; cat /etc/passwd`

### Insecure Direct Object Reference (IDOR)
- **File**: `src/main/java/com/example/controller/UserController.java` (getUserDetails method)
- **Description**: No authorization checks when accessing user data.
- **Example Attack**: Access `/users/1` to view another user's data without proper permissions.

### Sensitive Data Exposure
- **File**: `src/main/java/com/example/controller/UserController.java` (login method)
- **Description**: Storing username and password in cookies in plaintext.
- **Example Attack**: Inspect cookies to retrieve sensitive credentials.

### Insecure Deserialization
- **File**: `src/main/java/com/example/controller/UserController.java` (importData method)
- **Description**: Deserializing user input without proper validation.
- **Example Attack**: Send a malicious serialized object to execute arbitrary code.

### Plaintext Password Storage
- **File**: `src/main/java/com/example/model/User.java`
- **Description**: User passwords are stored and managed in plaintext.

### Sensitive Data in Logs
- **File**: Various locations
- **Description**: Sensitive information is logged via Log4j, including exception details and user data.

### Vulnerable Dependencies
- **File**: `pom.xml`
- **Description**: The application uses several outdated dependencies with known vulnerabilities:
  - Log4j 2.14.0 (vulnerable to Log4Shell)
  - Jackson 2.9.10 (multiple deserialization vulnerabilities)
  - Spring 5.2.0.RELEASE (various vulnerabilities)
  - Commons Collections 3.2.1 (deserialization vulnerabilities)

## Running the Application

1. Ensure you have Java 8+ and Maven installed

2. Set up a MySQL database named `vulnerable_db`

3. Build the application:
```
mvn clean package
```

4. Deploy the WAR file to a Java application server like Tomcat

## Warning

This application contains intentional security vulnerabilities and should only be used for testing and educational purposes. Do not use in production or deploy on a public-facing server. 