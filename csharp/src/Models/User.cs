using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace VulnerableDotNetApp.Models
{
    public class User
    {
        public int Id { get; set; }
        
        public string Username { get; set; }
        
        // VULNERABILITY: Password stored without annotation for sensitive data
        public string Password { get; set; }
        
        public string Email { get; set; }
        
        public string Bio { get; set; }
        
        public bool IsAdmin { get; set; }
        
        // VULNERABILITY: Includes password in ToString
        public override string ToString()
        {
            return $"User {{ Id = {Id}, Username = {Username}, Password = {Password}, Email = {Email}, IsAdmin = {IsAdmin} }}";
        }
    }
} 