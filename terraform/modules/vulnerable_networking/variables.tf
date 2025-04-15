variable "vnet_name" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "vulnerable-vnet"
}

variable "address_space" {
  # VULNERABILITY: No validation
  # VULNERABILITY: Overly broad CIDR blocks
  default = ["10.0.0.0/8"]
}

variable "subnet_name" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "vulnerable-subnet"
}

variable "subnet_address_prefix" {
  # VULNERABILITY: No validation
  default = ["10.0.1.0/24"]
}

variable "resource_group_name" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  # VULNERABILITY: No default - will error if not specified
}

variable "location" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "East US"
}

variable "resource_prefix" {
  # VULNERABILITY: No description
  # VULNERABILITY: No type constraint
  default = "vulnerable"
}

# VULNERABILITY: Missing required variable validation
# VULNERABILITY: No sensitive flags on sensitive variables
# VULNERABILITY: No descriptions to guide users 