namespace VulnerableFSharpApp

open System
open System.IO
open System.Text
open System.Security.Cryptography

// Vulnerability: Insecure cryptographic implementations
module Encryption =
    // Vulnerability: Hard-coded encryption key
    let private encryptionKey = "ThisIsAVeryInsecureKey123"
    
    // Vulnerability: Static initialization vector
    let private initializationVector = "1234567890abcdef"
    
    // Vulnerability: Weak encryption algorithm (DES)
    let encryptDES (plainText: string) =
        try
            // Vulnerability: Using obsolete and weak DES algorithm
            use des = new DESCryptoServiceProvider()
            
            // Vulnerability: Using hard-coded key and IV
            des.Key <- Encoding.UTF8.GetBytes(encryptionKey).AsSpan(0, 8).ToArray()
            des.IV <- Encoding.UTF8.GetBytes(initializationVector).AsSpan(0, 8).ToArray()
            
            let dataBytes = Encoding.UTF8.GetBytes(plainText)
            
            use memoryStream = new MemoryStream()
            use cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write)
            
            cryptoStream.Write(dataBytes, 0, dataBytes.Length)
            cryptoStream.FlushFinalBlock()
            
            Convert.ToBase64String(memoryStream.ToArray())
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "Encryption error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Weak decryption algorithm (DES)
    let decryptDES (cipherText: string) =
        try
            // Vulnerability: Using obsolete and weak DES algorithm
            use des = new DESCryptoServiceProvider()
            
            // Vulnerability: Using hard-coded key and IV
            des.Key <- Encoding.UTF8.GetBytes(encryptionKey).AsSpan(0, 8).ToArray()
            des.IV <- Encoding.UTF8.GetBytes(initializationVector).AsSpan(0, 8).ToArray()
            
            let dataBytes = Convert.FromBase64String(cipherText)
            
            use memoryStream = new MemoryStream(dataBytes)
            use cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Read)
            use reader = new StreamReader(cryptoStream)
            
            reader.ReadToEnd()
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "Decryption error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Weak hash algorithm (MD5)
    let hashMD5 (input: string) =
        try
            // Vulnerability: Using obsolete and weak MD5 algorithm
            use md5 = MD5.Create()
            
            let inputBytes = Encoding.UTF8.GetBytes(input)
            let hashBytes = md5.ComputeHash(inputBytes)
            
            // Convert to hex string
            BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "Hashing error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Using SHA1 (considered weak)
    let hashSHA1 (input: string) =
        try
            // Vulnerability: Using weak SHA1 algorithm
            use sha1 = SHA1.Create()
            
            let inputBytes = Encoding.UTF8.GetBytes(input)
            let hashBytes = sha1.ComputeHash(inputBytes)
            
            // Convert to hex string
            BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "Hashing error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Insecure password storage (no salt, weak hash)
    let hashPassword (password: string) =
        // Vulnerability: No salt
        // Vulnerability: Single iteration
        // Vulnerability: Using weak hash function
        hashMD5(password)
    
    // Vulnerability: Insecure password verification
    let verifyPassword (password: string) (hashedPassword: string) =
        // Vulnerability: Direct comparison of hashes
        let calculatedHash = hashPassword(password)
        calculatedHash = hashedPassword
    
    // Vulnerability: ECB mode encryption (AES)
    let encryptAES_ECB (plainText: string) =
        try
            // Vulnerability: Using AES in ECB mode
            use aes = Aes.Create()
            aes.Mode <- CipherMode.ECB  // Vulnerability: ECB mode preserves patterns
            aes.Padding <- PaddingMode.PKCS7
            
            // Vulnerability: Fixed key
            aes.Key <- Encoding.UTF8.GetBytes(encryptionKey.PadRight(32).Substring(0, 32))
            
            // ECB doesn't use an IV, but we'll set it anyway
            aes.IV <- new byte[16]  // Zero IV
            
            let dataBytes = Encoding.UTF8.GetBytes(plainText)
            
            use memoryStream = new MemoryStream()
            use cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write)
            
            cryptoStream.Write(dataBytes, 0, dataBytes.Length)
            cryptoStream.FlushFinalBlock()
            
            Convert.ToBase64String(memoryStream.ToArray())
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "AES-ECB encryption error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Insecure CBC mode with predictable IV
    let encryptAES_CBC (plainText: string) =
        try
            use aes = Aes.Create()
            aes.Mode <- CipherMode.CBC
            aes.Padding <- PaddingMode.PKCS7
            
            // Vulnerability: Hardcoded key
            aes.Key <- Encoding.UTF8.GetBytes(encryptionKey.PadRight(32).Substring(0, 32))
            
            // Vulnerability: Predictable IV
            aes.IV <- Encoding.UTF8.GetBytes(initializationVector.PadRight(16).Substring(0, 16))
            
            let dataBytes = Encoding.UTF8.GetBytes(plainText)
            
            use memoryStream = new MemoryStream()
            use cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write)
            
            cryptoStream.Write(dataBytes, 0, dataBytes.Length)
            cryptoStream.FlushFinalBlock()
            
            Convert.ToBase64String(memoryStream.ToArray())
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "AES-CBC encryption error: %s" (ex.ToString())
            ""
    
    // Vulnerability: Insecure random number generation
    let generateRandomToken (length: int) =
        // Vulnerability: Using Random instead of cryptographically secure RNG
        let random = new Random()
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        let result = new StringBuilder(length)
        for i = 1 to length do
            // Vulnerability: Predictable random sequence
            result.Append(chars.[random.Next(chars.Length)]) |> ignore
            
        result.ToString()
    
    // Vulnerability: Timing attack vulnerable comparison
    let constantTimeEquals (a: string) (b: string) =
        // Vulnerability: Early return on length mismatch
        if a.Length <> b.Length then
            false
        else
            // Vulnerability: Not actually constant time
            a = b
    
    // Vulnerability: Broken HMAC implementation
    let calculateHMAC (message: string) (key: string) =
        try
            // Vulnerability: Using MD5 for HMAC
            let keyBytes = Encoding.UTF8.GetBytes(key)
            use hmac = new HMACMD5(keyBytes)
            
            let messageBytes = Encoding.UTF8.GetBytes(message)
            let hashBytes = hmac.ComputeHash(messageBytes)
            
            Convert.ToBase64String(hashBytes)
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "HMAC calculation error: %s" (ex.ToString())
            ""
            
    // Vulnerability: RSA implementation with weak key size
    let generateRSAKeyPair() =
        try
            // Vulnerability: Using a 512-bit key (too small for RSA)
            use rsa = new RSACryptoServiceProvider(512)
            
            // Export the key information
            let publicKey = rsa.ExportParameters(false)
            let privateKey = rsa.ExportParameters(true)
            
            // Return the public and private keys as XML strings
            let publicKeyXml = rsa.ToXmlString(false)
            let privateKeyXml = rsa.ToXmlString(true)
            
            (publicKeyXml, privateKeyXml)
        with ex ->
            // Vulnerability: Exception reveals implementation details
            printfn "RSA key generation error: %s" (ex.ToString())
            ("", "") 