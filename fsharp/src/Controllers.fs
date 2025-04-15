namespace VulnerableFSharpApp.Controllers

open System
open System.IO
open System.Xml
open System.Xml.Serialization
open System.Text
open System.Text.RegularExpressions
open System.Security.Claims
open Microsoft.AspNetCore.Mvc
open Microsoft.AspNetCore.Authorization
open Microsoft.AspNetCore.Http
open Newtonsoft.Json
open YamlDotNet.Serialization
open VulnerableFSharpApp.Models
open VulnerableFSharpApp.DataAccess
open VulnerableFSharpApp.Authentication

[<ApiController>]
[<Route("[controller]")>]
type AuthController (httpContextAccessor: IHttpContextAccessor) =
    inherit ControllerBase()
    
    // VULNERABILITY: No rate limiting for login attempts
    [<HttpPost("login")>]
    member _.Login([<FromBody>] request: LoginRequest) =
        match AuthService.login request with
        | Some token -> 
            ActionResult<string>(Ok(token))
        | None -> 
            ActionResult<string>(Unauthorized("Invalid credentials"))
    
    // VULNERABILITY: Insecure user registration - no password requirements
    [<HttpPost("register")>]
    member _.Register([<FromBody>] user: User) =
        let success, message = AuthService.register user
        if success then
            ActionResult<string>(Ok(message))
        else
            ActionResult<string>(BadRequest(message))

[<ApiController>]
[<Route("[controller]")>]
type UserController (httpContextAccessor: IHttpContextAccessor) =
    inherit ControllerBase()
    
    // VULNERABILITY: SQL injection in search endpoint
    [<HttpGet("search")>]
    member _.SearchUsers([<FromQuery>] query: string) =
        let users = Database.searchUsers query
        
        // VULNERABILITY: Revealing sensitive information
        let results = {
            Query = query; // VULNERABILITY: Reflected user input
            Results = users |> List.map (fun u -> $"{u.Username} ({u.Email}) - {u.IsAdmin}");
            ResultCount = List.length users
        }
        
        ActionResult<SearchResult>(Ok(results))
    
    // VULNERABILITY: Insecure Direct Object Reference (IDOR)
    [<HttpGet("{id}")>]
    member _.GetUser(id: int) =
        // VULNERABILITY: No authorization check for user access
        // Should verify current user has permission to view this data
        let users = Database.searchUsers (id.ToString())
        match users with
        | user :: _ -> ActionResult<User>(Ok(user))
        | [] -> ActionResult<User>(NotFound("User not found"))

[<ApiController>]
[<Route("[controller]")>]
type FileController (httpContextAccessor: IHttpContextAccessor) =
    inherit ControllerBase()
    
    // VULNERABILITY: Path traversal vulnerability
    [<HttpGet("read")>]
    member _.ReadFile([<FromQuery>] path: string) =
        // VULNERABILITY: No path sanitization or authorization
        let content = FileSystem.readFile path
        ActionResult<string>(Ok(content))
    
    // VULNERABILITY: Path traversal in file upload
    [<HttpPost("write")>]
    member _.WriteFile([<FromBody>] request: FileUploadRequest) =
        // VULNERABILITY: No path sanitization or authorization
        let success = FileSystem.writeFile request
        if success then
            ActionResult<string>(Ok("File written successfully"))
        else
            ActionResult<string>(BadRequest("Failed to write file"))

[<ApiController>]
[<Route("[controller]")>]
type SystemController (httpContextAccessor: IHttpContextAccessor) =
    inherit ControllerBase()
    
    // VULNERABILITY: Command injection vulnerability
    [<HttpPost("execute")>]
    [<Authorize(Roles = "Admin")>] // Authorization exists but insufficient for dangerous operation
    member _.ExecuteCommand([<FromBody>] request: CommandRequest) =
        // VULNERABILITY: No command validation or sanitization
        let output = CommandExecution.executeCommand request
        ActionResult<string>(Ok(output))
    
    // VULNERABILITY: Insecure deserialization
    [<HttpPost("import")>]
    member _.ImportData([<FromBody>] data: SerializableData) =
        // VULNERABILITY: Type-based deserialization
        try
            let settings = JsonSerializerSettings()
            settings.TypeNameHandling <- TypeNameHandling.All
            
            // VULNERABILITY: Deserializing with type information
            let deserialized = JsonConvert.DeserializeObject(data.Data, Type.GetType(data.TypeName), settings)
            ActionResult<obj>(Ok(deserialized))
        with ex ->
            ActionResult<obj>(BadRequest($"Deserialization error: {ex.Message}"))
    
    // VULNERABILITY: XML External Entity (XXE) injection
    [<HttpPost("parse-xml")>]
    member _.ParseXml([<FromBody>] xml: string) =
        try
            // VULNERABILITY: Insecure XML parsing
            let xmlDoc = XmlDocument()
            xmlDoc.XmlResolver <- XmlUrlResolver() // Allows XXE
            xmlDoc.LoadXml(xml)
            
            let result = xmlDoc.DocumentElement.InnerText
            ActionResult<string>(Ok($"XML parsed: {result}"))
        with ex ->
            ActionResult<string>(BadRequest($"Error parsing XML: {ex.Message}"))
            
    // VULNERABILITY: YAML deserialization
    [<HttpPost("parse-yaml")>]
    member _.ParseYaml([<FromBody>] yaml: string) =
        try
            // VULNERABILITY: Unsafe YAML parsing
            let deserializer = DeserializerBuilder().Build()
            let result = deserializer.Deserialize<obj>(yaml)
            ActionResult<obj>(Ok(result))
        with ex ->
            ActionResult<obj>(BadRequest($"Error parsing YAML: {ex.Message}"))
            
    // VULNERABILITY: Open redirect
    [<HttpGet("redirect")>]
    member _.Redirect([<FromQuery>] url: string) =
        // VULNERABILITY: No URL validation
        Redirect(url) 