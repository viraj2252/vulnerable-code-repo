# Vulnerable Terraform Infrastructure Code

This directory contains deliberately vulnerable Terraform code for Azure infrastructure, designed to demonstrate common security issues in Infrastructure as Code (IaC).

## Vulnerabilities

### Secrets Management
- **File**: `main.tf`, `variables.tf`
- **Description**: Hardcoded credentials and secrets directly in Terraform code
- **Example**: Hardcoded Azure client ID, secret, subscription ID, and passwords
- **OWASP Relation**: A07:2021 - Identification and Authentication Failures

### Insecure Network Configuration
- **File**: `modules/vulnerable_networking/main.tf`, `network.tf`
- **Description**: Overly permissive network security groups and firewall rules
- **Example**: Security rules allowing all traffic (0.0.0.0/0) to sensitive ports (SSH, RDP)
- **OWASP Relation**: A01:2021 - Broken Access Control

### Sensitive Data Exposure
- **File**: `main.tf`, `outputs.tf`
- **Description**: Exposing sensitive data in outputs and state files
- **Example**: Public IP addresses and full NSG details exposed in outputs
- **OWASP Relation**: A02:2021 - Cryptographic Failures

### Resource Misconfiguration
- **File**: `main.tf`
- **Description**: Azure resources configured with insecure defaults
- **Examples**: 
  - Storage accounts with public access enabled
  - Key Vaults without proper protection mechanisms
  - SQL Server with firewall rules allowing all IPs
- **OWASP Relation**: A05:2021 - Security Misconfiguration

### Vulnerable Module Usage
- **File**: `main.tf`, `network.tf`
- **Description**: Using modules without version pinning and from untrusted sources
- **Example**: `module "vulnerable_storage" { source = "github.com/someuser/terraform-azure-vulnerable-storage" }`
- **OWASP Relation**: A06:2021 - Vulnerable and Outdated Components

### Missing Security Controls
- **File**: Various files
- **Description**: Omission of critical security controls
- **Examples**:
  - Missing encryption in transit and at rest
  - No logging or monitoring configuration
  - No threat detection policies on databases
- **OWASP Relation**: A04:2021 - Insecure Design

### Authentication Weaknesses
- **File**: `main.tf`
- **Description**: Insecure authentication methods
- **Example**: Using password authentication instead of SSH keys for VMs
- **OWASP Relation**: A07:2021 - Identification and Authentication Failures

### Insecure Defaults
- **File**: `variables.tf`
- **Description**: Insecure default values in variables
- **Examples**: Weak default passwords, overly permissive CIDR ranges
- **OWASP Relation**: A04:2021 - Insecure Design

## Resources Defined

1. Azure Resource Group
2. Azure Virtual Network and Subnets
3. Azure Storage Account and Container 
4. Azure Key Vault
5. Azure SQL Server
6. Azure Virtual Machine
7. Network Security Groups
8. Public IP Addresses

## Vulnerable External Module Reference

The Terraform configuration includes a reference to a fictional vulnerable external module:

```hcl
module "vulnerable_storage" {
  source = "github.com/someuser/terraform-azure-vulnerable-storage"
  # No version pinning
  # No integrity verification
}
```

## Running the Code

> **WARNING**: This Terraform code contains deliberate security vulnerabilities. Do not deploy it to production environments or any environment connected to the internet.

For educational purposes only, you can deploy this infrastructure to a sandbox Azure environment:

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy the infrastructure (NOT RECOMMENDED)
terraform apply
```

## Scanning with IaC Security Tools

This code is designed to be scanned with IaC security tools such as:

- Checkov
- Terrascan
- tfsec
- Snyk IaC
- Prisma Cloud

These tools should identify most or all of the deliberate vulnerabilities in the code.

## Remediation Guidance

For each vulnerability category, the secure approach would be:

1. **Secrets Management**: Use Azure Key Vault, environment variables, or a secrets manager
2. **Network Security**: Restrict access to specific IP ranges, use private endpoints
3. **Sensitive Data**: Mark outputs as sensitive, use remote state with encryption
4. **Resource Configuration**: Follow security best practices for each resource type
5. **Module Usage**: Pin module versions, use trusted sources, verify integrity
6. **Security Controls**: Implement encryption, logging, monitoring, and threat detection
7. **Authentication**: Use certificate or SSH key authentication instead of passwords
8. **Default Values**: Provide secure defaults, implement validation rules 