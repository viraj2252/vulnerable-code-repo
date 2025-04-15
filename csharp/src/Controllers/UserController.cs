using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using VulnerableDotNetApp.Models;
using YamlDotNet.Serialization;

namespace VulnerableDotNetApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;
        private readonly IConfiguration _configuration;
        
        // VULNERABILITY: Hardcoded connection string
        private readonly string _connectionString = "Server=localhost;Database=vulnerable_db;User Id=sa;Password=Password123!;";

        public UserController(ILogger<UserController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        // VULNERABILITY: SQL Injection
        [HttpGet("search")]
        public IActionResult SearchUsers(string username)
        {
            var users = new List<User>();
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // VULNERABILITY: Direct string concatenation in SQL query
                string query = "SELECT * FROM Users WHERE Username LIKE '%" + username + "%'";
                
                using (var command = new SqlCommand(query, connection))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            users.Add(new User
                            {
                                Id = Convert.ToInt32(reader["Id"]),
                                Username = reader["Username"].ToString(),
                                Email = reader["Email"].ToString()
                            });
                        }
                    }
                }
            }
            
            return Ok(users);
        }

        // VULNERABILITY: Path Traversal
        [HttpGet("download")]
        public IActionResult DownloadFile(string filename)
        {
            try
            {
                // VULNERABILITY: Unsanitized path allows directory traversal
                var filePath = filename;
                var fileBytes = System.IO.File.ReadAllBytes(filePath);
                
                return File(fileBytes, "application/octet-stream", Path.GetFileName(filePath));
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Information disclosure in error message
                return BadRequest($"Error downloading file: {ex.Message}");
            }
        }

        // VULNERABILITY: Command Injection
        [HttpGet("ping")]
        public IActionResult PingHost(string host)
        {
            try
            {
                if (string.IsNullOrEmpty(host))
                {
                    return BadRequest("Host parameter is required");
                }
                
                // VULNERABILITY: Unsanitized input to command
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "ping",
                    Arguments = host,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                var process = Process.Start(processStartInfo);
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                return Ok(output);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error executing command: {ex.Message}");
            }
        }

        // VULNERABILITY: Insecure Deserialization
        [HttpPost("import")]
        public IActionResult ImportData([FromBody] string serializedData)
        {
            try
            {
                // VULNERABILITY: Unsafe deserialization of user input
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All
                };
                
                var obj = JsonConvert.DeserializeObject(serializedData, settings);
                return Ok($"Data imported successfully: {obj}");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error importing data: {ex.Message}");
            }
        }

        // VULNERABILITY: Cross-Site Scripting (XSS)
        [HttpGet("profile/{id}")]
        public ContentResult GetUserProfile(int id)
        {
            var user = GetUserById(id);
            
            if (user == null)
            {
                return Content("User not found", "text/html");
            }
            
            // VULNERABILITY: Unsanitized user data directly in HTML
            var html = $@"
                <html>
                <head><title>User Profile</title></head>
                <body>
                    <h1>User Profile for {user.Username}</h1>
                    <p>Email: {user.Email}</p>
                    <p>Bio: {user.Bio}</p>
                </body>
                </html>
            ";
            
            return Content(html, "text/html");
        }

        // VULNERABILITY: XML External Entity (XXE) Injection
        [HttpPost("parse-xml")]
        public IActionResult ParseXml([FromBody] string xml)
        {
            try
            {
                // VULNERABILITY: Insecure XML parsing settings
                var xmlDoc = new XmlDocument();
                xmlDoc.XmlResolver = new XmlUrlResolver(); // Allows XXE
                xmlDoc.LoadXml(xml);
                
                var result = xmlDoc.DocumentElement.InnerText;
                return Ok($"XML parsed: {result}");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error parsing XML: {ex.Message}");
            }
        }

        // VULNERABILITY: Insecure Direct Object Reference (IDOR)
        [HttpGet("{id}")]
        public IActionResult GetUser(int id)
        {
            // VULNERABILITY: No authorization check
            var user = GetUserById(id);
            
            if (user == null)
            {
                return NotFound();
            }
            
            return Ok(user);
        }

        // VULNERABILITY: Open Redirect
        [HttpGet("redirect")]
        public IActionResult RedirectTo(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return BadRequest("URL parameter is required");
            }
            
            // VULNERABILITY: No validation of redirect URL
            return Redirect(url);
        }

        // VULNERABILITY: YAML Deserialization
        [HttpPost("config")]
        public IActionResult ParseYaml([FromBody] string yaml)
        {
            try
            {
                var deserializer = new DeserializerBuilder().Build();
                var config = deserializer.Deserialize<Dictionary<string, object>>(yaml);
                
                return Ok(config);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error parsing YAML: {ex.Message}");
            }
        }

        // Helper method to get a user by ID
        private User GetUserById(int id)
        {
            User user = null;
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string query = "SELECT * FROM Users WHERE Id = @Id";
                
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Id", id);
                    
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            user = new User
                            {
                                Id = Convert.ToInt32(reader["Id"]),
                                Username = reader["Username"].ToString(),
                                Email = reader["Email"].ToString(),
                                Bio = reader["Bio"]?.ToString()
                            };
                        }
                    }
                }
            }
            
            return user;
        }
    }
} 