# Vulnerable C# / .NET Application

This directory contains a deliberately vulnerable .NET Core application designed to demonstrate common security issues in C# web applications.

## Vulnerabilities

### SQL Injection
- **File**: `src/Controllers/UserController.cs` (SearchUsers method)
- **Description**: The application constructs SQL queries using string concatenation.
- **Example Attack**: Search with query parameter `%' OR 1=1 --`

### Command Injection
- **File**: `src/Controllers/UserController.cs` (PingHost method)
- **Description**: User input is passed directly to ProcessStartInfo without validation.
- **Example Attack**: `?host=localhost & type C:\windows\win.ini`

### Path Traversal
- **File**: `src/Controllers/UserController.cs` (DownloadFile method)
- **Description**: User-provided filename is used directly to access files.
- **Example Attack**: `?filename=../../../Windows/win.ini`

### Insecure Deserialization
- **File**: `src/Controllers/UserController.cs` (ImportData method)
- **Description**: Uses TypeNameHandling.All which allows deserialization attacks.
- **Example Attack**: Craft a JSON payload that executes arbitrary code during deserialization.

### Cross-Site Scripting (XSS)
- **File**: `src/Controllers/UserController.cs` (GetUserProfile method)
- **Description**: User data is directly rendered in HTML without encoding.
- **Example Attack**: Enter `<script>alert('XSS')</script>` in user bio.

### XML External Entity (XXE) Injection
- **File**: `src/Controllers/UserController.cs` (ParseXml method)
- **Description**: XML parsing with external entity resolution enabled.
- **Example Attack**: Submit XML with external entity references to read local files.

### Insecure Direct Object Reference (IDOR)
- **File**: `src/Controllers/UserController.cs` (GetUser method)
- **Description**: No authorization checks when accessing user data by ID.
- **Example Attack**: Access data for a different user by changing the ID parameter.

### Open Redirect
- **File**: `src/Controllers/UserController.cs` (RedirectTo method)
- **Description**: Redirect URLs are not validated.
- **Example Attack**: `?url=https://malicious-site.com`

### Information Disclosure
- **File**: Various locations
- **Description**: Detailed error messages exposed to client.

### Security Misconfiguration
- **File**: `src/Startup.cs` and `src/Program.cs`
- **Description**: Various security misconfigurations:
  - Development mode in production
  - No HTTPS redirection
  - No authentication/authorization
  - Permissive CORS policy
  - Binding to all network interfaces

### Insecure YAML Deserialization
- **File**: `src/Controllers/UserController.cs` (ParseYaml method)
- **Description**: YAML parsing without proper validation.

### Sensitive Data Exposure
- **File**: `src/Models/User.cs`
- **Description**: Password stored without annotation for sensitive data and included in ToString method.

### Vulnerable Dependencies
- **File**: `vulnerable-dotnet-app.csproj`
- **Description**: The application uses several outdated packages with known vulnerabilities.

## Running the Application

1. Ensure you have .NET Core 3.1+ installed

2. Set up a SQL Server database named `vulnerable_db`

3. Run the application:
```
cd src
dotnet run
```

4. Access the application at http://localhost:5000

## Warning

This application contains intentional security vulnerabilities and should only be used for testing and educational purposes. Do not use in production or deploy on a public-facing server. 