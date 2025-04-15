namespace VulnerableFSharpApp

open System
open System.Data
open System.Data.SqlClient
open System.Collections.Generic
open Newtonsoft.Json
open VulnerableFSharpApp

// Vulnerability: Database module with multiple security issues
module Database =
    // Vulnerability: Hardcoded connection string with credentials
    let connectionString = "Server=db.example.com;Database=AppDB;User Id=sa;Password=Password123!;"
    
    // Vulnerability: Connection not using connection pooling
    let createConnection() =
        let connection = new SqlConnection(connectionString)
        connection.Open()
        connection
    
    // Vulnerability: SQL injection through string concatenation
    let getUserByUsername (username: string) =
        use connection = createConnection()
        // Vulnerability: Unsafe string concatenation for SQL query
        use command = new SqlCommand($"SELECT * FROM Users WHERE Username = '{username}'", connection)
        
        use reader = command.ExecuteReader()
        if reader.Read() then
            Some {
                Id = reader.GetInt32(reader.GetOrdinal("Id"))
                Username = reader.GetString(reader.GetOrdinal("Username"))
                Password = reader.GetString(reader.GetOrdinal("Password"))
                Email = reader.GetString(reader.GetOrdinal("Email"))
                FirstName = reader.GetString(reader.GetOrdinal("FirstName"))
                LastName = reader.GetString(reader.GetOrdinal("LastName"))
                SocialSecurityNumber = 
                    if reader.IsDBNull(reader.GetOrdinal("SocialSecurityNumber")) then None
                    else Some(reader.GetString(reader.GetOrdinal("SocialSecurityNumber")))
                CreditCardNumber = 
                    if reader.IsDBNull(reader.GetOrdinal("CreditCardNumber")) then None
                    else Some(reader.GetString(reader.GetOrdinal("CreditCardNumber")))
                CreditCardCVV = 
                    if reader.IsDBNull(reader.GetOrdinal("CreditCardCVV")) then None
                    else Some(reader.GetString(reader.GetOrdinal("CreditCardCVV")))
                DateOfBirth = 
                    if reader.IsDBNull(reader.GetOrdinal("DateOfBirth")) then None
                    else Some(reader.GetDateTime(reader.GetOrdinal("DateOfBirth")))
                Address = 
                    if reader.IsDBNull(reader.GetOrdinal("Address")) then None
                    else Some(reader.GetString(reader.GetOrdinal("Address")))
                IsAdmin = reader.GetBoolean(reader.GetOrdinal("IsAdmin"))
                ApiKeys = None // Just for simplicity here
            }
        else
            None
    
    // Vulnerability: Second-order SQL injection with unsafe dynamic SQL
    let executeRawQuery (query: string) =
        // Vulnerability: Direct execution of user-provided SQL
        use connection = createConnection()
        use command = new SqlCommand(query, connection)
        
        use reader = command.ExecuteReader()
        let results = new List<IDictionary<string, obj>>()
        
        while reader.Read() do
            let row = new Dictionary<string, obj>()
            for i = 0 to reader.FieldCount - 1 do
                row.Add(reader.GetName(i), reader.GetValue(i))
            results.Add(row)
            
        results
    
    // Vulnerability: Insecure credential verification
    let verifyCredentials (username: string) (password: string) =
        // Vulnerability: Password stored and compared in plaintext
        match getUserByUsername username with
        | Some user when user.Password = password -> Some user
        | _ -> None
    
    // Vulnerability: Insecure data access with no access control
    let getAllUsers() =
        // Vulnerability: No permission checking
        use connection = createConnection()
        use command = new SqlCommand("SELECT * FROM Users", connection)
        
        use reader = command.ExecuteReader()
        let users = new List<User>()
        
        while reader.Read() do
            let user = {
                Id = reader.GetInt32(reader.GetOrdinal("Id"))
                Username = reader.GetString(reader.GetOrdinal("Username"))
                // Vulnerability: Exposing all user data including passwords
                Password = reader.GetString(reader.GetOrdinal("Password"))
                Email = reader.GetString(reader.GetOrdinal("Email"))
                FirstName = reader.GetString(reader.GetOrdinal("FirstName"))
                LastName = reader.GetString(reader.GetOrdinal("LastName"))
                SocialSecurityNumber = 
                    if reader.IsDBNull(reader.GetOrdinal("SocialSecurityNumber")) then None
                    else Some(reader.GetString(reader.GetOrdinal("SocialSecurityNumber")))
                CreditCardNumber = 
                    if reader.IsDBNull(reader.GetOrdinal("CreditCardNumber")) then None
                    else Some(reader.GetString(reader.GetOrdinal("CreditCardNumber")))
                CreditCardCVV = 
                    if reader.IsDBNull(reader.GetOrdinal("CreditCardCVV")) then None
                    else Some(reader.GetString(reader.GetOrdinal("CreditCardCVV")))
                DateOfBirth = 
                    if reader.IsDBNull(reader.GetOrdinal("DateOfBirth")) then None
                    else Some(reader.GetDateTime(reader.GetOrdinal("DateOfBirth")))
                Address = 
                    if reader.IsDBNull(reader.GetOrdinal("Address")) then None
                    else Some(reader.GetString(reader.GetOrdinal("Address")))
                IsAdmin = reader.GetBoolean(reader.GetOrdinal("IsAdmin"))
                ApiKeys = None // Just for simplicity here
            }
            users.Add(user)
            
        users
    
    // Vulnerability: Unsafe serialization of database results
    let getSerializedUserData (userId: int) =
        // Vulnerability: Retrieving sensitive data with no filtering
        use connection = createConnection()
        use command = new SqlCommand($"SELECT * FROM Users WHERE Id = {userId}", connection)
        
        use reader = command.ExecuteReader()
        if reader.Read() then
            let userData = new Dictionary<string, obj>()
            for i = 0 to reader.FieldCount - 1 do
                userData.Add(reader.GetName(i), reader.GetValue(i))
                
            // Vulnerability: Serializing sensitive data with no protection
            JsonConvert.SerializeObject(userData)
        else
            "{}"
    
    // Vulnerability: Unsafe bulk update with no validation
    let bulkUpdateUserData (userId: int) (updates: Dictionary<string, obj>) =
        // Vulnerability: No validation of update fields
        use connection = createConnection()
        
        // Vulnerability: Directly using user-provided field names in SQL
        let setClauses = 
            updates
            |> Seq.map (fun kvp -> $"{kvp.Key} = @{kvp.Key}")
            |> String.concat ", "
            
        // Vulnerability: Potential SQL injection in setClauses variable
        use command = new SqlCommand($"UPDATE Users SET {setClauses} WHERE Id = {userId}", connection)
        
        // Adding parameters but still vulnerable to schema issues
        for kvp in updates do
            command.Parameters.AddWithValue($"@{kvp.Key}", kvp.Value)
            
        command.ExecuteNonQuery()
            
    // Vulnerability: Insecure transaction handling
    let transferFunds (fromUserId: int) (toUserId: int) (amount: decimal) =
        // Vulnerability: No proper transaction isolation
        use connection = createConnection()
        use transaction = connection.BeginTransaction(IsolationLevel.ReadUncommitted) // Vulnerability: Dirty reads possible
        
        try
            // Vulnerability: No proper validation or authorization
            let withdrawCommand = new SqlCommand($"UPDATE Accounts SET Balance = Balance - {amount} WHERE UserId = {fromUserId}", connection, transaction)
            let depositCommand = new SqlCommand($"UPDATE Accounts SET Balance = Balance + {amount} WHERE UserId = {toUserId}", connection, transaction)
            
            // Vulnerability: No check if enough funds available
            withdrawCommand.ExecuteNonQuery() |> ignore
            
            // Vulnerability: Transaction can be partially committed if error happens
            depositCommand.ExecuteNonQuery() |> ignore
            
            transaction.Commit()
            true
        with
        | ex -> 
            // Vulnerability: Exception details exposed
            printfn "Error: %s" ex.Message
            transaction.Rollback()
            false 