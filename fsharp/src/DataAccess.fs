namespace VulnerableFSharpApp.DataAccess

open System
open System.Data
open System.Data.SqlClient
open System.IO
open VulnerableFSharpApp.Models

// VULNERABILITY: Hard-coded connection string
module Constants =
    // VULNERABILITY: Plaintext connection string with credentials
    let connectionString = "Server=localhost;Database=vulnerable_db;User Id=sa;Password=Password123!;"

module Database =
    // VULNERABILITY: SQL Injection vulnerability
    let getUserByUsername (username: string) =
        use connection = new SqlConnection(Constants.connectionString)
        connection.Open()
        
        // VULNERABILITY: String interpolation in SQL query
        let query = $"SELECT * FROM Users WHERE Username = '{username}'"
        
        use command = new SqlCommand(query, connection)
        use reader = command.ExecuteReader()
        
        if reader.Read() then
            Some {
                Id = reader.GetInt32(0)
                Username = reader.GetString(1)
                Password = reader.GetString(2) // VULNERABILITY: Password in plaintext
                Email = reader.GetString(3)
                IsAdmin = reader.GetBoolean(4)
            }
        else
            None
    
    // VULNERABILITY: SQL Injection in login
    let authenticateUser (username: string) (password: string) =
        use connection = new SqlConnection(Constants.connectionString)
        connection.Open()
        
        // VULNERABILITY: String concatenation in SQL
        let query = sprintf "SELECT * FROM Users WHERE Username = '%s' AND Password = '%s'" username password
        
        use command = new SqlCommand(query, connection)
        use reader = command.ExecuteReader()
        
        reader.Read()

    // VULNERABILITY: Unsafe error handling exposing DB details
    let searchUsers (searchTerm: string) =
        try
            use connection = new SqlConnection(Constants.connectionString)
            connection.Open()
            
            // VULNERABILITY: String interpolation in SQL query
            let query = $"SELECT * FROM Users WHERE Username LIKE '%{searchTerm}%' OR Email LIKE '%{searchTerm}%'"
            
            use command = new SqlCommand(query, connection)
            use reader = command.ExecuteReader()
            
            let mutable results = []
            while reader.Read() do
                let user = {
                    Id = reader.GetInt32(0)
                    Username = reader.GetString(1)
                    Password = reader.GetString(2) // VULNERABILITY: Password included in search results
                    Email = reader.GetString(3)
                    IsAdmin = reader.GetBoolean(4)
                }
                results <- user :: results
                
            results
        with ex ->
            // VULNERABILITY: Detailed error exposure
            printfn "Database Error: %s" ex.Message
            printfn "Connection String: %s" Constants.connectionString
            []

module FileSystem =
    // VULNERABILITY: Path traversal
    let readFile (filepath: string) =
        // VULNERABILITY: No path sanitization
        if File.Exists(filepath) then
            File.ReadAllText(filepath)
        else
            sprintf "File not found: %s" filepath
    
    // VULNERABILITY: Path traversal in file writing
    let writeFile (request: FileUploadRequest) =
        try
            // VULNERABILITY: No path sanitization
            File.WriteAllText(request.FilePath, request.Content)
            true
        with ex ->
            printfn "File write error: %s" ex.Message
            false

module CommandExecution =
    open System.Diagnostics
    
    // VULNERABILITY: Command injection
    let executeCommand (request: CommandRequest) =
        try
            let psi = ProcessStartInfo()
            psi.FileName <- request.Command
            psi.Arguments <- request.Arguments
            psi.RedirectStandardOutput <- true
            psi.UseShellExecute <- false
            psi.CreateNoWindow <- true
            
            use proc = Process.Start(psi)
            let output = proc.StandardOutput.ReadToEnd()
            proc.WaitForExit()
            output
        with ex ->
            sprintf "Error executing command: %s" ex.Message 