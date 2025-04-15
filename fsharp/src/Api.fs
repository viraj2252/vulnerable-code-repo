namespace VulnerableFSharpApp

open System
open System.Text
open System.Text.Json
open System.IO
open Models
open Database
open System.Net
open System.Xml
open System.Xml.Serialization
open Newtonsoft.Json

module Api =
    // Vulnerability: No input validation on API endpoints
    type ApiResponse<'T> = {
        Success: bool
        Data: 'T option
        Message: string option
    }

    // Vulnerability: Insecure deserialization of user-controlled data
    let deserializeRequest<'T> (requestBody: string) =
        try
            // Vulnerability: No validation of input before deserialization
            let options = JsonSerializerOptions()
            options.PropertyNameCaseInsensitive <- true
            JsonSerializer.Deserialize<'T>(requestBody, options) |> Some
        with
        | ex -> 
            printfn "Error deserializing request: %s" ex.Message
            None

    // Vulnerability: No CSRF protection
    let handleLogin (requestBody: string) =
        match deserializeRequest<{| Username: string; Password: string |}> requestBody with
        | Some credentials ->
            // Vulnerability: Insecure credential verification
            let isAuthenticated = Database.verifyUserCredentials credentials.Username credentials.Password
            
            if isAuthenticated then
                // Vulnerability: Weak session management
                let authToken = Guid.NewGuid().ToString()
                printfn "User %s logged in successfully" credentials.Username
                
                // Vulnerability: Excessive data in response
                let userData = Database.getUserByUsername credentials.Username
                match userData with
                | Some user ->
                    {
                        Success = true
                        Data = Some {| Token = authToken; User = user |} // Vulnerability: Returning sensitive user data
                        Message = Some "Login successful"
                    }
                | None ->
                    {
                        Success = false
                        Data = None
                        Message = Some "User data not found"
                    }
            else
                {
                    Success = false
                    Data = None
                    Message = Some "Invalid username or password"
                }
        | None ->
            {
                Success = false
                Data = None
                Message = Some "Invalid request format"
            }

    // Vulnerability: No authorization check
    let handleGetUserProfile (userId: string) (authHeader: string option) =
        // Vulnerability: No proper token validation
        match authHeader with
        | Some token ->
            // Vulnerability: Insecure direct object reference
            try
                let userIdInt = int userId
                match Database.getUserData userIdInt with
                | Some userData ->
                    {
                        Success = true
                        Data = Some userData // Vulnerability: Returning all user data including sensitive information
                        Message = None
                    }
                | None ->
                    {
                        Success = false
                        Data = None
                        Message = Some "User not found"
                    }
            with
            | ex ->
                {
                    Success = false
                    Data = None
                    Message = Some (sprintf "Error: %s" ex.Message)
                }
        | None ->
            {
                Success = false
                Data = None
                Message = Some "Unauthorized access"
            }
    
    // Vulnerability: Insecure file operations
    let handleFileUpload (filename: string) (content: byte[]) =
        // Vulnerability: Path traversal
        let filePath = Path.Combine("uploads", filename)
        
        try
            // Vulnerability: No validation of file type or content
            File.WriteAllBytes(filePath, content)
            {
                Success = true
                Data = Some {| FilePath = filePath |}
                Message = Some "File uploaded successfully"
            }
        with
        | ex ->
            {
                Success = false
                Data = None
                Message = Some (sprintf "Error uploading file: %s" ex.Message)
            }
    
    // Vulnerability: Insecure data exposure
    let handleExportUserData (userId: string) =
        try
            let userIdInt = int userId
            match Database.getUserData userIdInt with
            | Some userData ->
                // Vulnerability: Sensitive data exposure
                let userJson = JsonSerializer.Serialize(userData)
                let filePath = Path.Combine("exports", sprintf "user_%d.json" userIdInt)
                Directory.CreateDirectory(Path.GetDirectoryName(filePath)) |> ignore
                File.WriteAllText(filePath, userJson)
                
                {
                    Success = true
                    Data = Some {| FilePath = filePath |}
                    Message = Some "User data exported successfully"
                }
            | None ->
                {
                    Success = false
                    Data = None
                    Message = Some "User not found"
                }
        with
        | ex ->
            {
                Success = false
                Data = None
                Message = Some (sprintf "Error exporting user data: %s" ex.Message)
            }
    
    // Vulnerability: Command injection
    let handleSystemCommand (command: string) =
        try
            // Vulnerability: Executing user-controlled input as system command
            let process = System.Diagnostics.Process.Start("cmd.exe", sprintf "/c %s" command)
            process.WaitForExit()
            
            {
                Success = true
                Data = Some {| ExitCode = process.ExitCode |}
                Message = Some "Command executed successfully"
            }
        with
        | ex ->
            {
                Success = false
                Data = None
                Message = Some (sprintf "Error executing command: %s" ex.Message)
            }
    
    // Vulnerability: XXE vulnerability
    let handleXmlImport (xmlContent: string) =
        try
            // Vulnerability: Unsafe XML parsing
            let xmlDoc = new System.Xml.XmlDocument()
            xmlDoc.XmlResolver <- new System.Xml.XmlUrlResolver() // Vulnerability: Enables XXE
            
            // Vulnerability: Processing external entities
            let settings = new System.Xml.XmlReaderSettings()
            settings.DtdProcessing <- System.Xml.DtdProcessing.Parse
            
            use stringReader = new StringReader(xmlContent)
            use reader = System.Xml.XmlReader.Create(stringReader, settings)
            xmlDoc.Load(reader)
            
            {
                Success = true
                Data = Some {| NodeCount = xmlDoc.ChildNodes.Count |}
                Message = Some "XML processed successfully"
            }
        with
        | ex ->
            {
                Success = false
                Data = None
                Message = Some (sprintf "Error processing XML: %s" ex.Message)
            }
            
    // Vulnerability: Open redirect
    let handleRedirect (redirectUrl: string) =
        // Vulnerability: No validation of redirect URL
        {
            Success = true
            Data = Some {| RedirectUrl = redirectUrl |}
            Message = Some "Redirecting..."
        }

    // Vulnerability: API module with multiple security issues
    let handleLoginRequest (request: HttpListenerRequest) (response: HttpListenerResponse) =
        try
            // Vulnerability: Reading plain text credentials from request
            use reader = new StreamReader(request.InputStream, request.ContentEncoding)
            let requestBody = reader.ReadToEnd()
            
            // Vulnerability: Using deserialization without validation
            let loginData = JsonConvert.DeserializeObject<LoginRequest>(requestBody)
            
            // Vulnerability: No rate limiting for login attempts
            match Database.verifyCredentials loginData.Username loginData.Password with
            | Some user ->
                // Vulnerability: Weak session management
                let sessionId = Guid.NewGuid().ToString()
                
                // Store session with unlimited lifetime
                let session = {
                    Id = sessionId
                    UserId = user.Id
                    IpAddress = request.RemoteEndPoint.Address.ToString()
                    CreatedAt = DateTime.Now
                    ExpiresAt = DateTime.Now.AddDays(365.0) // Vulnerability: Extremely long session
                    UserAgent = request.UserAgent
                }
                
                // Vulnerability: Returning sensitive user data
                let responseData = {|
                    Success = true
                    Message = "Login successful"
                    SessionId = sessionId
                    User = user // Vulnerability: Returns full user object with sensitive data
                |}
                
                // Vulnerability: No secure flag for cookies
                response.AppendCookie(new Cookie("session_id", sessionId))
                response.StatusCode <- 200
                response.ContentType <- "application/json"
                
                // Vulnerability: No content security policy
                let responseJson = JsonConvert.SerializeObject(responseData)
                let buffer = Encoding.UTF8.GetBytes(responseJson)
                response.ContentLength64 <- int64 buffer.Length
                response.OutputStream.Write(buffer, 0, buffer.Length)
            | None ->
                // Vulnerability: Leaking information about failed login
                let responseData = {|
                    Success = false
                    Message = "Invalid username or password" // Vulnerability: Leaks which credentials are invalid
                |}
                
                response.StatusCode <- 401
                response.ContentType <- "application/json"
                
                let responseJson = JsonConvert.SerializeObject(responseData)
                let buffer = Encoding.UTF8.GetBytes(responseJson)
                response.ContentLength64 <- int64 buffer.Length
                response.OutputStream.Write(buffer, 0, buffer.Length)
        with ex ->
            // Vulnerability: Exposing exception details to client
            let errorResponse = {|
                Success = false
                Error = ex.ToString() // Vulnerability: Returning full exception details
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: No access control or authentication check
    let handleGetAllUsersRequest (request: HttpListenerRequest) (response: HttpListenerResponse) =
        // Vulnerability: No authorization check before returning sensitive data
        let users = Database.getAllUsers()
        
        // Vulnerability: Returning all user data including sensitive information
        let responseJson = JsonConvert.SerializeObject(users)
        
        response.StatusCode <- 200
        response.ContentType <- "application/json"
        
        let buffer = Encoding.UTF8.GetBytes(responseJson)
        response.ContentLength64 <- int64 buffer.Length
        response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: XML External Entity (XXE) processing
    let handleXmlImport (request: HttpListenerRequest) (response: HttpListenerResponse) =
        try
            // Vulnerability: No XML validation
            use reader = new StreamReader(request.InputStream, request.ContentEncoding)
            let requestBody = reader.ReadToEnd()
            
            // Vulnerability: Creating XML reader without secure settings
            let xmlDoc = new XmlDocument()
            
            // Vulnerability: DTD processing enabled leading to XXE
            xmlDoc.XmlResolver <- new XmlUrlResolver()
            xmlDoc.LoadXml(requestBody)
            
            // Process the XML and respond
            response.StatusCode <- 200
            response.ContentType <- "application/json"
            
            let responseData = {|
                Success = true
                Message = "XML import successful"
                ElementCount = xmlDoc.DocumentElement.ChildNodes.Count
            |}
            
            let responseJson = JsonConvert.SerializeObject(responseData)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
        with ex ->
            // Vulnerability: Exception details exposure
            let errorResponse = {|
                Success = false
                Error = ex.ToString()
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: Server-side request forgery (SSRF)
    let handleProxyRequest (request: HttpListenerRequest) (response: HttpListenerResponse) =
        // Vulnerability: Processing URL from request without validation
        let targetUrl = request.QueryString.Get("url")
        
        // Vulnerability: No URL validation allows internal network access
        try
            // Create web request to the specified URL
            let webRequest = WebRequest.Create(targetUrl)
            
            // Vulnerability: Forward all headers without filtering
            for headerName in request.Headers.AllKeys do
                webRequest.Headers.Add(headerName, request.Headers.Get(headerName))
                
            // Make the request
            use webResponse = webRequest.GetResponse()
            use responseStream = webResponse.GetResponseStream()
            
            // Forward response headers
            response.StatusCode <- (webResponse :?> HttpWebResponse).StatusCode |> int
            response.ContentType <- webResponse.ContentType
            
            // Forward response body
            let buffer = Array.zeroCreate<byte> 8192
            let mutable bytesRead = responseStream.Read(buffer, 0, buffer.Length)
            
            while bytesRead > 0 do
                response.OutputStream.Write(buffer, 0, bytesRead)
                bytesRead <- responseStream.Read(buffer, 0, buffer.Length)
                
        with ex ->
            // Vulnerability: Error details exposure
            let errorResponse = {|
                Success = false
                Error = ex.ToString()
                URL = targetUrl // Vulnerability: Exposing target URL
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: Insecure file upload handling
    let handleFileUpload (request: HttpListenerRequest) (response: HttpListenerResponse) =
        try
            // Check if it's a multipart form
            if request.ContentType.StartsWith("multipart/form-data") then
                // Parse boundary
                let boundary = request.ContentType.Split('=').[1]
                
                // Read form data
                use reader = new StreamReader(request.InputStream, request.ContentEncoding)
                let requestBody = reader.ReadToEnd()
                
                // Split by boundary
                let parts = requestBody.Split([|"--" + boundary|], StringSplitOptions.None)
                
                // Find file part
                let filePart = parts |> Array.find (fun p -> p.Contains("filename="))
                
                // Extract filename
                let filenameStart = filePart.IndexOf("filename=") + 10
                let filenameEnd = filePart.IndexOf("\"", filenameStart)
                let filename = filePart.Substring(filenameStart, filenameEnd - filenameStart)
                
                // Vulnerability: No validation of filename or content
                // Vulnerability: Saving files with user-provided names
                
                // Find content start
                let contentStart = filePart.IndexOf("\r\n\r\n") + 4
                let content = filePart.Substring(contentStart).TrimEnd('\r', '\n', '-')
                
                // Vulnerability: Saving files to an unsecured location
                // Vulnerability: Path traversal possible in filename
                let targetPath = Path.Combine("uploads", filename)
                File.WriteAllText(targetPath, content)
                
                // Vulnerability: Serving the file directly
                let fileUrl = $"/uploads/{filename}"
                
                let responseData = {|
                    Success = true
                    Message = "File uploaded successfully"
                    FileName = filename
                    Url = fileUrl
                |}
                
                response.StatusCode <- 200
                response.ContentType <- "application/json"
                
                let responseJson = JsonConvert.SerializeObject(responseData)
                let buffer = Encoding.UTF8.GetBytes(responseJson)
                response.ContentLength64 <- int64 buffer.Length
                response.OutputStream.Write(buffer, 0, buffer.Length)
            else
                response.StatusCode <- 400
                response.ContentType <- "application/json"
                
                let responseData = {|
                    Success = false
                    Message = "Not a multipart form data request"
                |}
                
                let responseJson = JsonConvert.SerializeObject(responseData)
                let buffer = Encoding.UTF8.GetBytes(responseJson)
                response.ContentLength64 <- int64 buffer.Length
                response.OutputStream.Write(buffer, 0, buffer.Length)
        with ex ->
            // Vulnerability: Error details exposure
            let errorResponse = {|
                Success = false
                Error = ex.ToString()
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: Insecure deserialization
    let handleObjectDeserialization (request: HttpListenerRequest) (response: HttpListenerResponse) =
        try
            // Vulnerability: Using insecure deserialization without validation
            use reader = new StreamReader(request.InputStream, request.ContentEncoding)
            let requestBody = reader.ReadToEnd()
            
            // Vulnerability: Using TypeNameHandling.All allows code execution
            let settings = new JsonSerializerSettings()
            settings.TypeNameHandling <- TypeNameHandling.All
            
            // Vulnerability: Deserializing with type information can lead to remote code execution
            let deserializedObject = JsonConvert.DeserializeObject(requestBody, settings)
            
            // Process the object
            let objectType = deserializedObject.GetType().FullName
            
            let responseData = {|
                Success = true
                Message = "Object deserialized successfully"
                Type = objectType
                Properties = deserializedObject.GetType().GetProperties() |> Array.map (fun p -> p.Name)
            |}
            
            response.StatusCode <- 200
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(responseData)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
        with ex ->
            // Vulnerability: Error details exposure
            let errorResponse = {|
                Success = false
                Error = ex.ToString()
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: Command injection
    let handleSystemCommand (request: HttpListenerRequest) (response: HttpListenerResponse) =
        // Vulnerability: Taking command input from request
        let command = request.QueryString.Get("cmd")
        
        // Vulnerability: Not validating or sanitizing command input
        try
            // Start the process
            let psi = new System.Diagnostics.ProcessStartInfo()
            psi.FileName <- "cmd.exe" // For Windows
            psi.Arguments <- $"/c {command}" // Vulnerability: Direct command injection
            psi.RedirectStandardOutput <- true
            psi.UseShellExecute <- false
            psi.CreateNoWindow <- true
            
            let process = System.Diagnostics.Process.Start(psi)
            let output = process.StandardOutput.ReadToEnd()
            process.WaitForExit()
            
            // Return the command output
            let responseData = {|
                Success = true
                Command = command
                Output = output
                ExitCode = process.ExitCode
            |}
            
            response.StatusCode <- 200
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(responseData)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
        with ex ->
            // Vulnerability: Error details exposure
            let errorResponse = {|
                Success = false
                Command = command
                Error = ex.ToString()
            |}
            
            response.StatusCode <- 500
            response.ContentType <- "application/json"
            
            let responseJson = JsonConvert.SerializeObject(errorResponse)
            let buffer = Encoding.UTF8.GetBytes(responseJson)
            response.ContentLength64 <- int64 buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
    
    // Vulnerability: Open redirect
    let handleRedirect (request: HttpListenerRequest) (response: HttpListenerResponse) =
        // Vulnerability: Taking redirect URL directly from request parameter
        let redirectUrl = request.QueryString.Get("url")
        
        // Vulnerability: No validation of redirect URL
        
        // Set redirect response
        response.StatusCode <- 302
        response.RedirectLocation <- redirectUrl
        response.Close()
        
    // Vulnerability: Business logic with insecure direct object reference
    let getUserProfile (request: HttpListenerRequest) (response: HttpListenerResponse) =
        // Vulnerability: Taking user ID directly from URL without access control
        let userId = int(request.QueryString.Get("id"))
        
        // Vulnerability: No access control check
        // Vulnerability: No authentication check
        
        // Get and return user data with sensitive information
        let userData = Database.getSerializedUserData(userId)
        
        response.StatusCode <- 200
        response.ContentType <- "application/json"
        
        let buffer = Encoding.UTF8.GetBytes(userData)
        response.ContentLength64 <- int64 buffer.Length
        response.OutputStream.Write(buffer, 0, buffer.Length)
        
    // Start the API server
    let startServer (port: int) =
        let listener = new HttpListener()
        listener.Prefixes.Add($"http://+:{port}/")
        listener.Start()
        
        // Vulnerability: No TLS/SSL
        printfn $"Vulnerable API server started on port {port}"
        
        async {
            while true do
                try
                    let! context = Async.FromBeginEnd(listener.BeginGetContext, listener.EndGetContext)
                    let request = context.Request
                    let response = context.Response
                    
                    // Vulnerability: No input validation
                    // Vulnerability: No request rate limiting
                    
                    // Vulnerability: No proper routing with validation
                    match request.Url.AbsolutePath with
                    | "/api/login" when request.HttpMethod = "POST" ->
                        handleLoginRequest request response
                    | "/api/users" when request.HttpMethod = "GET" ->
                        handleGetAllUsersRequest request response
                    | "/api/import/xml" when request.HttpMethod = "POST" ->
                        handleXmlImport request response
                    | "/api/proxy" when request.HttpMethod = "GET" ->
                        handleProxyRequest request response
                    | "/api/upload" when request.HttpMethod = "POST" ->
                        handleFileUpload request response
                    | "/api/deserialize" when request.HttpMethod = "POST" ->
                        handleObjectDeserialization request response
                    | "/api/exec" when request.HttpMethod = "GET" ->
                        handleSystemCommand request response
                    | "/api/redirect" when request.HttpMethod = "GET" ->
                        handleRedirect request response
                    | "/api/user/profile" when request.HttpMethod = "GET" ->
                        getUserProfile request response
                    | _ ->
                        // Vulnerability: Detailed error for invalid routes
                        response.StatusCode <- 404
                        response.ContentType <- "application/json"
                        
                        let responseData = {|
                            Error = "Route not found"
                            RequestedPath = request.Url.AbsolutePath
                            Method = request.HttpMethod
                            AvailableRoutes = [|
                                "/api/login (POST)"
                                "/api/users (GET)"
                                "/api/import/xml (POST)"
                                "/api/proxy (GET)"
                                "/api/upload (POST)"
                                "/api/deserialize (POST)"
                                "/api/exec (GET)"
                                "/api/redirect (GET)"
                                "/api/user/profile (GET)"
                            |]
                        |}
                        
                        let responseJson = JsonConvert.SerializeObject(responseData)
                        let buffer = Encoding.UTF8.GetBytes(responseJson)
                        response.ContentLength64 <- int64 buffer.Length
                        response.OutputStream.Write(buffer, 0, buffer.Length)
                    
                    // Vulnerability: No proper response cleanup
                    response.Close()
                with ex ->
                    // Vulnerability: Logging sensitive exception details
                    printfn "Error handling request: %s" (ex.ToString())
        } |> Async.Start 