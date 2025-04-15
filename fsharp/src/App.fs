namespace VulnerableFSharpApp

module App =
    open System
    open Microsoft.AspNetCore.Builder
    open Microsoft.AspNetCore.Hosting
    open Microsoft.Extensions.DependencyInjection
    open Microsoft.Extensions.Logging
    open VulnerableFSharpApp.Models
    open VulnerableFSharpApp.DataAccess
    open VulnerableFSharpApp.Authentication
    open System.IO

    // Vulnerability: Insecure initialization with hardcoded values
    let initializeApp() =
        // Vulnerability: Sensitive data exposure - hardcoded admin credentials
        let admin = { 
            Id = 1
            Username = "admin"
            Password = "admin123" // Plaintext password
            Email = "admin@example.com"
            Role = "Administrator"
            LastLogin = DateTime.Now
            ApiKey = "1234-abcd-5678-efgh" // Hardcoded API key
            PersonalData = { 
                FullName = "Admin User"; 
                SocialSecurityNumber = "123-45-6789"; // Sensitive data 
                DateOfBirth = DateTime.Parse("1980-01-01")
                Address = "123 Admin St, Server City"
            }
        }

        // Vulnerability: Insecure data storage
        let dataPath = Path.Combine(Directory.GetCurrentDirectory(), "data")
        Directory.CreateDirectory(dataPath) |> ignore
        
        // Vulnerability: Storing plaintext sensitive data
        let usersFilePath = Path.Combine(dataPath, "users.json")
        if not (File.Exists(usersFilePath)) then
            // Vulnerability: Using insecure serialization
            let json = Newtonsoft.Json.JsonConvert.SerializeObject(
                [admin], 
                Newtonsoft.Json.Formatting.Indented,
                Newtonsoft.Json.JsonSerializerSettings(TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All)
            )
            File.WriteAllText(usersFilePath, json)
        
        // Vulnerability: Hardcoded database connection string with credentials
        let dbConfig = {
            ConnectionString = "Server=dbserver;Database=appdb;User Id=sa;Password=Password123!"
            MaxConnections = 100
            Timeout = 30
            EnablePooling = true
        }
        
        // Vulnerability: Storing configuration in plaintext
        let configFilePath = Path.Combine(dataPath, "config.json")
        let configJson = Newtonsoft.Json.JsonConvert.SerializeObject(dbConfig, Newtonsoft.Json.Formatting.Indented)
        File.WriteAllText(configFilePath, configJson)
        
        printfn "Application initialized with default data"

    // Vulnerability: Demonstrating command injection
    let performMaintenance() =
        // Vulnerability: Unsafe command execution
        let logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "logs", "app.log")
        Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)) |> ignore
        
        // Vulnerability: Creating a dangerous command string that will be executed
        let command = sprintf "echo Application maintenance completed at %s > %s" (DateTime.Now.ToString()) logFilePath
        CommandExecution.executeCommand command |> ignore
        
        printfn "Maintenance completed"

    // Vulnerability: Demonstrating insecure file operations
    let setupSampleData() =
        let dataDir = Path.Combine(Directory.GetCurrentDirectory(), "sample_data")
        Directory.CreateDirectory(dataDir) |> ignore
        
        // Vulnerability: Creating sample files with insecure access
        let sampleData = """
<users>
    <user>
        <username>user1</username>
        <password>password123</password>
    </user>
    <user>
        <username>user2</username>
        <password>abc123</password>
    </user>
</users>
"""
        // Vulnerability: Path traversal - no validation of path
        FileSystem.writeFile (Path.Combine(dataDir, "users.xml")) sampleData |> ignore
        
        printfn "Sample data created"

    // Vulnerability: Demonstrating weak authentication
    let simulateLogin username password =
        // Vulnerability: Weak password handling
        let isValid = AuthService.login username password
        
        match isValid with
        | true -> 
            printfn "Login successful for %s" username
            let token = TokenService.generateJwtToken username "user"
            printfn "Generated token: %s" token
        | false -> 
            printfn "Login failed for %s" username
            
    // Vulnerability: Demonstrating SQL injection
    let demonstrateSearch searchTerm =
        printfn "Searching for: %s" searchTerm
        
        // Vulnerability: Directly using user input in SQL query
        match Database.searchUsers searchTerm with
        | Ok results -> 
            printfn "Found %d results" (List.length results)
            results |> List.iter (fun u -> printfn "- %s (%s)" u.Username u.Email)
        | Error e -> 
            printfn "Search error: %s" e
            
    // Entry point for testing vulnerable functions
    let runSampleOperations() =
        printfn "Starting vulnerable F# application demo..."
        
        initializeApp()
        performMaintenance()
        setupSampleData()
        
        // Demonstrate login with default admin
        simulateLogin "admin" "admin123"
        
        // Demonstrate SQL injection vulnerability
        demonstrateSearch "a' OR '1'='1"
        
        printfn "Vulnerable F# application demo completed" 