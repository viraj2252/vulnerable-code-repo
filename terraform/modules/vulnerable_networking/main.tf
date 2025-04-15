# VULNERABILITY: Module with no provider constraints
# VULNERABILITY: No version pinning for the module

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  address_space       = var.address_space
  location            = var.location
  resource_group_name = var.resource_group_name
  
  # VULNERABILITY: No network security group associated
}

resource "azurerm_subnet" "subnet" {
  name                 = var.subnet_name
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.subnet_address_prefix
  
  # VULNERABILITY: Service endpoints not enabled
  # VULNERABILITY: Network security group not associated
}

resource "azurerm_network_interface" "nic" {
  name                = "${var.resource_prefix}-nic"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.public_ip.id  # VULNERABILITY: Public IP associated
  }
}

resource "azurerm_public_ip" "public_ip" {
  name                = "${var.resource_prefix}-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"  # VULNERABILITY: Static public IP
  
  # VULNERABILITY: No DDoS protection
}

# VULNERABILITY: Permissive security rules allowing all traffic
resource "azurerm_network_security_group" "open_nsg" {
  name                = "${var.resource_prefix}-open-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  # VULNERABILITY: Allow all inbound traffic
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # VULNERABILITY: Allow all outbound traffic
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# VULNERABILITY: Network Watcher not enabled
# VULNERABILITY: Flow logs not enabled

# VULNERABILITY: Bastion host not implemented
# VULNERABILITY: VPN gateway not implemented 