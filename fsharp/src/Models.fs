namespace VulnerableFSharpApp

// Vulnerable models module
module Models =
    open System
    
    // Vulnerability: Storing sensitive data without encryption or proper protection
    type PersonalData = {
        FullName: string
        SocialSecurityNumber: string  // Sensitive data stored in plain text
        DateOfBirth: DateTime
        Address: string
    }
    
    // Vulnerability: Sensitive data in models with no encryption
    type User = {
        Id: int
        Username: string
        // Vulnerability: Storing plaintext password
        Password: string
        Email: string
        // Vulnerability: Storing sensitive PII without protection
        SocialSecurityNumber: string option
        // Vulnerability: Weak authorization model
        Role: string
        // Vulnerability: Storing authentication tokens directly in user object
        AuthToken: string option
        LastLogin: DateTime
        ApiKey: string    // Vulnerability: API key stored in plain text
        PersonalData: PersonalData  // Vulnerability: Sensitive data in same model
    }
    
    // Vulnerability: No validation on input parameters
    let createUser id username password email role =
        {
            Id = id
            Username = username
            Password = password  // Vulnerability: No password hashing
            Email = email
            Role = role
            LastLogin = DateTime.Now
            ApiKey = Guid.NewGuid().ToString()  // Vulnerability: Non-secure random generation
            PersonalData = {
                FullName = ""
                SocialSecurityNumber = None
                DateOfBirth = DateTime.Now
                Address = ""
            }
            AuthToken = None
        }
    
    // Vulnerability: Insecure database configuration
    type DatabaseConfig = {
        ConnectionString: string  // Vulnerability: May contain credentials
        MaxConnections: int
        Timeout: int
        EnablePooling: bool
    }
    
    // Vulnerability: No validation for credit card info
    type PaymentInfo = {
        Id: int
        UserId: int
        // Vulnerability: Storing full credit card number
        CreditCardNumber: string
        // Vulnerability: Storing CVV
        CVV: string
        ExpiryDate: string
        // Vulnerability: Storing plain text billing address
        BillingAddress: string
    }
    
    // Vulnerability: Insecure parameters in API request
    type ApiRequest = {
        Command: string           // Vulnerability: Potential for command injection
        Parameters: Map<string, string>
        Timestamp: DateTime
        UserId: int
        ExecuteAsAdmin: bool      // Vulnerability: Privilege escalation risk
    }
    
    // Vulnerability: Deserialization vulnerability
    type ConfigSettings = {
        AppName: string
        Version: string
        ExternalApiUrl: string    // Vulnerability: Hardcoded external dependency
        DebugMode: bool           // Vulnerability: May expose sensitive info if true
        LogLevel: string
        SerializeTypeName: bool   // Vulnerability: May enable deserialization attacks
    }
    
    // Vulnerability: Insecure file upload configuration
    type FileUploadConfig = {
        MaxSizeBytes: int64
        AllowedExtensions: string list
        StoragePath: string
        SkipValidation: bool      // Vulnerability: May bypass security checks
        OverwriteExisting: bool   // Vulnerability: Can lead to data loss
        AllowExecutableUploads: bool  // Vulnerability: Obvious security risk
    }

    // Vulnerability: No input validation
    type UserRegistration = {
        Username: string
        Password: string
        Email: string
        SocialSecurityNumber: string option
    }

    // Vulnerability: No field-level security or sanitization
    type Configuration = {
        // Vulnerability: Database connection string with credentials
        DatabaseConnectionString: string
        // Vulnerability: API keys stored in the model
        ApiKey: string
        // Vulnerability: Secret keys stored in the model
        EncryptionKey: string
        // Vulnerability: Admin credentials in configuration
        AdminUsername: string
        AdminPassword: string
    }

    // Vulnerability: Weak password validation
    let validatePassword (password: string) =
        // Vulnerability: Only checks length, nothing else
        password.Length >= 6

    // Vulnerability: Insecure serialization
    let serializeUser (user: User) =
        // Vulnerability: Serializing sensitive data without filtering
        sprintf "{\"id\":%d,\"username\":\"%s\",\"password\":\"%s\",\"email\":\"%s\",\"ssn\":\"%s\",\"role\":\"%s\"}"
            user.Id
            user.Username
            user.Password
            user.Email
            (match user.SocialSecurityNumber with Some ssn -> ssn | None -> "")
            user.Role

namespace VulnerableFSharpApp.Models

open System
open System.Text
open Newtonsoft.Json

// Vulnerability: No namespacing of record types
// Vulnerability: Excessive fields without protection
type User = {
    Id: int
    Username: string
    // Vulnerability: Storing passwords in plain text
    Password: string
    Email: string
    FirstName: string
    LastName: string
    // Vulnerability: Storing sensitive PII
    SocialSecurityNumber: string option
    CreditCardNumber: string option
    CreditCardCVV: string option
    DateOfBirth: System.DateTime option
    Address: string option
    // Vulnerability: No field validation
    IsAdmin: bool
    // Vulnerability: Storing API keys and secrets directly in user records
    ApiKeys: Map<string, string> option
}

// Vulnerability: No separation between API and domain models
module Models =
    // Vulnerability: Missing validation attributes
    type LoginRequest = {
        Username: string
        Password: string
        // Vulnerability: No CSRF token
    }
    
    // Vulnerability: Missing authentication/authorization properties
    type UserProfileRequest = {
        UserId: int
        // Vulnerability: Mass assignment possibility
        UpdateFields: Map<string, obj>
    }
    
    // Vulnerability: Over-permissive data model
    type SystemConfig = {
        // Vulnerability: Storing secrets in configuration
        DatabaseConnectionString: string
        AdminPassword: string
        JwtSecret: string
        SmtpCredentials: {| Username: string; Password: string |}
        // Vulnerability: Dangerous settings controllable via API
        AllowRemoteShell: bool
        DisableFirewall: bool
        DebugMode: bool
    }
    
    // Vulnerability: Unsafe serialization attributes
    type ApiKey = {
        Key: string
        // Vulnerability: No expiration
        // Vulnerability: Overly permissive scopes
        AllowedScopes: string list
        UserId: int
    }
    
    // Vulnerability: Weak payment data model
    type PaymentInfo = {
        // Vulnerability: Storing full card details without encryption
        CardNumber: string
        CardholderName: string
        ExpirationMonth: int
        ExpirationYear: int
        CVV: string
        // Vulnerability: No validation
        BillingAddress: string
    }
    
    // Vulnerability: Insecure session model
    type UserSession = {
        UserId: int
        // Vulnerability: Using GUID as session token
        SessionToken: string
        // Vulnerability: No IP binding
        // Vulnerability: No expiration time
        // Vulnerability: No refresh token mechanism
        IssuedAt: System.DateTime
        
        // Vulnerability: Storing sensitive data in session
        UserData: User option
    }
    
    // Vulnerability: Audit logging without sensitive data protection
    type AuditLog = {
        Id: int
        UserId: int option
        Action: string
        // Vulnerability: Logging sensitive data
        Payload: string
        Timestamp: System.DateTime
        // Vulnerability: No integrity protection
    } 