namespace VulnerableFSharpApp

open System
open System.IO
open VulnerableFSharpApp
open Database
open Api

module Program =
    // Vulnerability: Unsafe initialization
    let initializeApp () =
        try
            // Vulnerability: Creating directories without proper permissions
            if not (Directory.Exists("uploads")) then
                Directory.CreateDirectory("uploads") |> ignore
                printfn "Created uploads directory"
                
            // Vulnerability: Creating a temporary admin user with hard-coded credentials
            // Simulating database initialization 
            printfn "Initializing database with default admin user"
            printfn "Username: admin, Password: admin123"
            
            // Vulnerability: Printing sensitive configuration to console
            let config = {
                DatabaseConnectionString = Database.connectionString
                ApiKey = "SK1234567890_ThisIsNotSecure"
                EncryptionKey = "ThisIsAVeryInsecureEncryptionKey12345"
                AdminPassword = "SuperSecretAdminPassword"
                DebugMode = true
                AllowRemoteConnections = true
                MaxLoginAttempts = 0  // Unlimited login attempts
                SessionTimeoutMinutes = 0  // No session timeout
                LoggingEnabled = true
                LogLevel = "DEBUG"  // Maximum logging, including sensitive data
            }
            
            printfn "Application configuration:"
            printfn "Database Connection: %s" config.DatabaseConnectionString
            printfn "API Key: %s" config.ApiKey
            printfn "Encryption Key: %s" config.EncryptionKey
            printfn "Admin Password: %s" config.AdminPassword
            printfn "Debug Mode: %b" config.DebugMode
            
            true
        with ex ->
            // Vulnerability: Exposing exception details
            printfn "ERROR DURING INITIALIZATION: %s" (ex.ToString())
            false
    
    // Vulnerability: Unsafe command-line argument parsing
    [<EntryPoint>]
    let main argv =
        printfn "Starting Vulnerable F# Application..."
        
        // Vulnerability: No validation of command-line arguments
        let port = 
            if argv.Length > 0 then
                // Vulnerability: No error handling for non-integer input
                int argv.[0]
            else
                8080
                
        // Vulnerability: No input validation for other command line parameters
        let configPath =
            if argv.Length > 1 then
                // Vulnerability: Path traversal risk
                argv.[1]
            else
                "config.json"
                
        if initializeApp() then
            // Vulnerability: Starting server without TLS
            printfn "Starting API server on port %d" port
            
            // Vulnerability: Privileged port binding without authentication
            Api.startServer port
            
            printfn "Press any key to stop the server..."
            Console.ReadKey() |> ignore
            0  // Return success
        else
            printfn "Application initialization failed!"
            1  // Return error 