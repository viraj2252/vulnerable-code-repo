namespace VulnerableFSharpApp.Authentication

open System
open System.Text
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open VulnerableFSharpApp.Models
open VulnerableFSharpApp.DataAccess

module SecurityConfig =
    // VULNERABILITY: Hardcoded secret key
    let JWT_SECRET = "ThisIsAVeryInsecureSecretKeyThatShouldBeStoredInASecureVault"
    // VULNERABILITY: Long token expiration
    let TOKEN_EXPIRATION_DAYS = 30
    // VULNERABILITY: Weak hashing algorithm
    let HASH_ALGORITHM = "MD5"
    
module PasswordUtils =
    open System.Security.Cryptography
    
    // VULNERABILITY: Using weak hashing algorithm (MD5)
    let hashPassword (password: string) =
        use md5 = MD5.Create()
        let inputBytes = Encoding.ASCII.GetBytes(password)
        let hashBytes = md5.ComputeHash(inputBytes)
        
        let sb = new StringBuilder()
        for i in 0 .. hashBytes.Length - 1 do
            sb.Append(hashBytes.[i].ToString("X2")) |> ignore
        sb.ToString()
    
    // VULNERABILITY: Timing attack vulnerability due to string comparison
    let verifyPassword (plainPassword: string) (hashedPassword: string) =
        let hashedInput = hashPassword plainPassword
        hashedInput = hashedPassword
        
module TokenService =
    // VULNERABILITY: No token validation or refresh
    let generateJwtToken (user: User) =
        let securityKey = SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityConfig.JWT_SECRET))
        let credentials = SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
        
        let claims = [|
            Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString())
            Claim(JwtRegisteredClaimNames.UniqueName, user.Username)
            Claim(ClaimTypes.Role, if user.IsAdmin then "Admin" else "User")
            Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        |]
        
        let expires = DateTime.Now.AddDays(float SecurityConfig.TOKEN_EXPIRATION_DAYS)
        
        let tokenDescriptor = JwtSecurityToken(
            issuer = "vulnerable-fsharp-app",
            audience = "vulnerable-fsharp-app",
            claims = claims,
            expires = expires,
            signingCredentials = credentials
        )
        
        let tokenHandler = JwtSecurityTokenHandler()
        tokenHandler.WriteToken(tokenDescriptor)
    
    // VULNERABILITY: No validation of token beyond expiration
    let validateToken (token: string) =
        let tokenHandler = JwtSecurityTokenHandler()
        let validationParameters = TokenValidationParameters(
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityConfig.JWT_SECRET)),
            ValidateIssuer = false, // VULNERABILITY: No issuer validation
            ValidateAudience = false, // VULNERABILITY: No audience validation
            ClockSkew = TimeSpan.Zero
        )
        
        try
            let principal = tokenHandler.ValidateToken(token, validationParameters, ref null)
            Some principal
        with
        | _ -> None

module AuthService =
    // VULNERABILITY: No rate limiting on login attempts
    let login (request: LoginRequest) =
        let userOption = Database.getUserByUsername request.Username
        
        match userOption with
        | Some user ->
            // VULNERABILITY: Direct password comparison
            if user.Password = request.Password then
                let token = TokenService.generateJwtToken user
                Some token
            else
                None
        | None -> None
    
    // VULNERABILITY: No proper error feedback (potential username enumeration)
    let register (user: User) =
        let existingUser = Database.getUserByUsername user.Username
        
        match existingUser with
        | Some _ -> 
            false, "Username already exists" // VULNERABILITY: Reveals existence of username
        | None ->
            // CODE INJECTION POINT: User registration would typically insert into database
            // Simulating successful registration
            true, "User registered successfully"

module Authentication =
    open System
    open System.Text
    open System.Security.Cryptography
    open Models
    open Database
    
    // Vulnerability: Weak hashing function (MD5)
    let hashPassword (password: string) =
        use md5 = MD5.Create()
        let inputBytes = Encoding.ASCII.GetBytes(password)
        let hashBytes = md5.ComputeHash(inputBytes)
        
        let sb = new StringBuilder()
        for i in 0 .. hashBytes.Length - 1 do
            sb.Append(hashBytes.[i].ToString("X2")) |> ignore
        sb.ToString()
    
    // Vulnerability: Predictable and weak token generation
    let generateAuthToken (username: string) =
        // Vulnerability: Using predictable seed for "random" token
        let random = new Random(username.GetHashCode())
        let tokenBytes = Array.zeroCreate<byte> 16
        random.NextBytes(tokenBytes)
        
        Convert.ToBase64String(tokenBytes)
    
    // Vulnerability: Insecure login mechanism
    let login (username: string) (password: string) =
        // Vulnerability: Uses direct password comparison instead of secure hash comparison
        if authenticateUser username password then
            let token = generateAuthToken username
            // Vulnerability: No expiration time for token
            Some token
        else
            None
    
    // Vulnerability: No rate limiting for login attempts
    let verifyLogin (username: string) (password: string) (failedAttempts: int) =
        // Vulnerability: No account lockout regardless of failed attempts count
        match getUserByUsername username with
        | Some user ->
            if user.Password = password then
                true
            else
                // Vulnerability: Information disclosure through different error messages
                printfn "Invalid password for user: %s" username
                false
        | None ->
            // Vulnerability: Username enumeration
            printfn "User not found: %s" username
            false
    
    // Vulnerability: Insecure password reset
    let resetPassword (email: string) =
        // Vulnerability: Generates predictable temporary password
        let temporaryPassword = email.Split('@').[0] + "123!"
        
        // Vulnerability: Should email password reset link, not actual password
        printfn "Temporary password for %s: %s" email temporaryPassword
        
        // Vulnerability: Password should be hashed before storage
        executeRawSql $"UPDATE Users SET Password = '{temporaryPassword}' WHERE Email = '{email}'"
        
        temporaryPassword
    
    // Vulnerability: IDOR (Insecure Direct Object Reference)
    let getUserProfile (userId: int) (requesterId: int) =
        // Vulnerability: No access control check
        // Any user can access any other user's profile data
        getUserById userId
    
    // Vulnerability: Insecure session management
    let userSessions = System.Collections.Generic.Dictionary<string, string>()
    
    // Vulnerability: No secure session mechanism
    let createSession (username: string) =
        let sessionId = Guid.NewGuid().ToString()
        userSessions.Add(sessionId, username)
        // Vulnerability: No secure cookie flags, no expiration
        sessionId
    
    // Vulnerability: Insecure permission check
    let hasAdminAccess (user: User) =
        // Vulnerability: Uses a role string instead of proper permission system
        user.Role.ToLower().Contains("admin")
    
    // Vulnerability: Broken authentication due to insecure comparison
    let verifyApiKey (providedKey: string) (storedKey: string) =
        // Vulnerability: Non-constant time comparison (timing attack vulnerability)
        providedKey = storedKey 