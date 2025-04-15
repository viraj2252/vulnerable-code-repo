provider "azurerm" {
  # VULNERABILITY: No version constraint
  # VULNERABILITY: No feature block required for azurerm 2.0+
  
  # VULNERABILITY: Hardcoded credentials
  subscription_id = "11111111-2222-3333-4444-555555555555"
  client_id       = "11111111-2222-3333-4444-555555555555"
  client_secret   = "supersecretkey123!"
  tenant_id       = "11111111-2222-3333-4444-555555555555"
}

# VULNERABILITY: Vulnerable external module without version pinning
module "vulnerable_storage" {
  source = "github.com/someuser/terraform-azure-vulnerable-storage"
  
  resource_group_name  = var.resource_group_name
  storage_account_name = "vulnerablestorage${random_string.random.result}"
  location             = var.location
}

# VULNERABILITY: Hard-coded secrets in locals
locals {
  admin_password = "Password123!"
  api_key        = "sk_test_12345678901234567890"
  database_password = "db_password_123"
}

resource "random_string" "random" {
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# VULNERABILITY: Storage account with public access
resource "azurerm_storage_account" "storage" {
  name                     = "vulnerablestorage${random_string.random.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  # VULNERABILITY: Insecure TLS version
  min_tls_version          = "TLS1_0"
  
  # VULNERABILITY: Public network access enabled
  public_network_access_enabled = true
  
  # VULNERABILITY: Allows anonymous access to blobs
  allow_blob_public_access = true
}

# VULNERABILITY: Blob container with public access
resource "azurerm_storage_container" "container" {
  name                  = "data"
  storage_account_name  = azurerm_storage_account.storage.name
  
  # VULNERABILITY: Container publicly accessible
  container_access_type = "blob"
}

# VULNERABILITY: Virtual machine with password authentication
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "vulnerable-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"
  
  # VULNERABILITY: Password authentication instead of SSH keys
  admin_password                  = local.admin_password
  disable_password_authentication = false
  
  network_interface_ids = [
    azurerm_network_interface.nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS" # VULNERABILITY: Outdated OS version
    version   = "latest"
  }
}

# VULNERABILITY: Network security group with overly permissive rules
resource "azurerm_network_security_group" "nsg" {
  name                = "vulnerable-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # VULNERABILITY: SSH open to the world
  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*" # VULNERABILITY: Open to all IPs
    destination_address_prefix = "*"
  }

  # VULNERABILITY: RDP open to the world
  security_rule {
    name                       = "RDP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*" # VULNERABILITY: Open to all IPs
    destination_address_prefix = "*"
  }
}

# VULNERABILITY: Azure SQL Server with firewall rule allowing all Azure services
resource "azurerm_sql_server" "sql" {
  name                         = "vulnerable-sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = local.database_password

  # VULNERABILITY: No threat detection policy
}

# VULNERABILITY: Firewall rule allowing all Azure IPs
resource "azurerm_sql_firewall_rule" "allow_azure_services" {
  name                = "AllowAllWindowsAzureIps"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_sql_server.sql.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}

# VULNERABILITY: Firewall rule allowing all IPs
resource "azurerm_sql_firewall_rule" "allow_all" {
  name                = "AllowAll"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_sql_server.sql.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}

# VULNERABILITY: Key Vault with no access policies
resource "azurerm_key_vault" "vault" {
  name                       = "vulnerable-vault-${random_string.random.result}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  
  # VULNERABILITY: Soft delete not enabled
  # soft_delete_enabled         = false
  
  # VULNERABILITY: Purge protection not enabled
  # purge_protection_enabled    = false
  
  # VULNERABILITY: Public network access
  public_network_access_enabled = true
} 