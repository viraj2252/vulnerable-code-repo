variable "resource_group_name" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "vulnerable-rg"
}

variable "location" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "East US"
}

# VULNERABILITY: No validation for sensitive info
variable "admin_username" {
  default = "adminuser"
}

# VULNERABILITY: Plain text sensitive variable
variable "admin_password" {
  # VULNERABILITY: Default password in plain text
  default = "Password123!"
  # VULNERABILITY: No sensitive = true attribute
}

# VULNERABILITY: Broad CIDR range
variable "allowed_ip_range" {
  default = "0.0.0.0/0"
}

variable "tenant_id" {
  # VULNERABILITY: Hardcoded value as default
  default = "11111111-2222-3333-4444-555555555555"
}

# VULNERABILITY: Using default credentials
variable "storage_access_key" {
  default = "DefaultAccessKey123!"
}

# VULNERABILITY: Insecure environment configuration
variable "environment" {
  default = "development"
  # VULNERABILITY: No validation for allowed environments
} 