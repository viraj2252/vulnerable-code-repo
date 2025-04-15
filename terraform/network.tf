# VULNERABILITY: Using local module without version
module "vulnerable_network" {
  source = "./modules/vulnerable_networking"
  
  vnet_name           = "main-vulnerable-vnet"
  address_space       = ["10.0.0.0/16"]
  subnet_name         = "vulnerable-subnet"
  subnet_address_prefix = ["10.0.2.0/24"]
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  resource_prefix     = "main"
}

# VULNERABILITY: Public IP directly referenced for resources
resource "azurerm_network_interface" "nic" {
  name                = "vulnerable-vm-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = module.vulnerable_network.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_public_ip.id
  }
}

# VULNERABILITY: Public IP without DDoS protection
resource "azurerm_public_ip" "vm_public_ip" {
  name                = "vulnerable-vm-ip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  
  # VULNERABILITY: No tags for resource identification
  # VULNERABILITY: No zones defined for high availability
}

# VULNERABILITY: No association of NSG with network interface
# VULNERABILITY: No proper network segmentation
# VULNERABILITY: No Azure Bastion for secure RDP/SSH access 