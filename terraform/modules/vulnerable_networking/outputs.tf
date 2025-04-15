output "vnet_id" {
  value = azurerm_virtual_network.vnet.id
  # VULNERABILITY: No description
}

output "subnet_id" {
  value = azurerm_subnet.subnet.id
  # VULNERABILITY: No description
}

output "network_interface_id" {
  value = azurerm_network_interface.nic.id
  # VULNERABILITY: No description
}

# VULNERABILITY: Exposing sensitive details
output "public_ip" {
  value = azurerm_public_ip.public_ip.ip_address
  # VULNERABILITY: No description
  # VULNERABILITY: No sensitive = true
}

# VULNERABILITY: Exposing complete resource details
output "full_network_security_group" {
  value = azurerm_network_security_group.open_nsg
  # VULNERABILITY: Exposes all NSG details including rules
} 