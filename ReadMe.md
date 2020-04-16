# SecurityCenterAutomation

These Modules (Cmdlets/DSC) provide the basics for automating the management of Tenable's Security Center Vulnerability Assessment & Management solution.  These modules have been tested on both 5.6 and 5.8 and is considered a work in progress.

## Installation
```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the "*SecurityCenterAutomation" folders to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)

# Cmdlet module
    Import-Module SecurityCenterAutomation 

# DSC module
    Import-DSCResource -module xSecurityCenter

# Get commands in the module
    Get-Command -Module SecurityCenterAutomation

# Get help for a command
    Get-Help Connect-SecurityCenter -Full
```

# Cmdlet Module

## Examples

### Create the commonly used Variables

```powershell
$ComputerName = 'SecurityCenterIpAddress'
$password = "SomePassword"
# Security Center 'Administrator' role credential
$AdminCreds = [pscredential]::new('admin', (ConvertTo-SecureString $password -AsPlainText -Force))
# Security Center 'Security Manager' role credential
$SecmanCreds = [pscredential]::new('secman', (ConvertTo-SecureString $password -AsPlainText -Force))
```

### Connect-SecurityCenter

Every Cmdlet in the module has the ability to take in a ComputerName and Credential parameter.  If you do not want to pass these parameters to every Cmdlet you can call Connect-SecurityCenter and it will cache this information for the life of the session, or 15 minutes, whichever is shortest.  

```PowerShell
Connect-SecurityCenter -ComputerName $ComputerName -Credential $AdminCreds
```

### FeedFile

```powershell
# Update Security Center with a downloaded feed file
Update-scFeed -ComputerName $ComputerName -Credential $AdminCreds -Path <path>\CM-239615-SecurityCenterFeed48.tar.gz -Type sc
```

### AuditFiles and AuditFileTemplates

```powershell
# Returns a list of all AuditFileTemplates
Get-ScAuditFileTemplate -ComputerName $ComputerName -Credential $AdminCreds 
# Get a specific AuditFileTemplate by name
$auditFileTemplate = Get-ScAuditFileTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
# Returns a list of all the AuditFiles currently defined
Get-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds
# Create a new Windows audit file based on the "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15" template
New-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name "MyNewAuditFile" -AuditFileTemplateId @{id = $auditFileTemplate.Id}
```

### Policy Credentials

```powershell
# Create a new policy credential that will store the 'Admin Creds'
New-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewAdminCred' -PolicyCredential $AdminCreds
# Returns a list of all the policy credentials currently defined
Get-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds
# Get a specific PolicyCredential by name
$policyCred = Get-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewAdminCred'
```

### Scan Policies

```powershell
# Returns a list of all the ScanPolicies currently defined
Get-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds
# Returns a list of all the ScanPolicyTemplates currently defined
Get-ScScanPolicyTemplate -ComputerName $ComputerName -Credential $AdminCreds
# Get a specific ScanPolicyTemplate by name 
$policyTemplate = Get-ScScanPolicyTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name 'SCAP and OVAL Auditing'
$PolicyTemplateId = @{id = $policyTemplate.Id} 
# Create a new ScanPolicy
$auditFile = Get-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewAuditFile'
$auditFileId = @{id = $AuditFile.Id}
New-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewScanPolicy' -AuditFiles $auditFileId -PolicyTemplateId $PolicyTemplateId
# Get a specific ScanPolicy by name
$policy = Get-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewScanPolicy'
```

### Assets

```powershell
# Creates a new Asset type
New-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds -Name 'MySqlServers' -type 'static' -DefinedIps @('192.0.0.100', '192.0.0.200')
# Returns a list of all the Assets currently defined
Get-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds
# Get a specific Asset by name
$assets = Get-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds -name 'MySqlServers' 
```

### Reports

```powershell
# Returns a list of all the Reports currently defined
Get-ScReportDefinition -ComputerName $ComputerName -Credential $SecmanCreds
# Get a specific Report by name
$reports = Get-ScReportDefinition -ComputerName $ComputerName -Credential $SecmanCreds -Name 'Critical and Exploitable Vulnerabilities Report'
```

### Repository
```powershell
# Returns a list of all the Repositories currently defined
Get-ScRepository -ComputerName $ComputerName -Credential $AdminCreds
# Get a specific Repository by name
$repository = Get-ScRepository -ComputerName $ComputerName -Credential $AdminCreds -Name 'Default_Repository'
```

### ActiveScans
```powershell
# Returns a list of all the ActiveScans currently defined
Get-ScActiveScan -ComputerName $ComputerName -Credential $SecmanCreds
# Create a new ActiveScan
$params = @{
    ComputerName = $ComputerName
    Credential = $SecmanCreds
    Name = 'MyNewScanPolicy'
    Description = 'Powershell ROCKS!'
    Assets = @{id = $assets.Id}
    ScanPolicyId = @{id = $Policy.Id}
    PolicyCredential = @(@{id = $policyCred.Id})
    Reports = @(@{id = $reports.id; reportSource = 'individual'})
    RepositoryId = @{id = $repository.id}
    type = 'policy'
}

New-ScActiveScan @params
# Run a specific ActiveScan
Start-ScScan -ComputerName $ComputerName -Credential $SecmanCreds -ScanName 'MyNewScanPolicy' -MaxScanWaitTimeInMinutes 5
```

# DSC Module

## Resources

- **xScActiveScan** This resource allows for the creation/modification/removal of an ActiveScan.
- **xScAsset** This resource allows for the creation/modification/removal of an Asset.
- **xScAuditFile** This resource allows for the creation/modification/removal of an AuditFile policy.
- **xScCredential** This resource allows for the creation/modification/removal of an policy credential.
- **xScScanPolicy** This resource allows for the creation/modification/removal of an Scan policy.

### xScActiveScan

- **Name** Friendly name for the ActiveScan we wish to create/modify/remove
- **Ensure** Specify whether the ActiveScan should be present or removed
- **ComputerName** FQDN or IpAddress of the Tenable SecurityCenter server
- **Description** Optional desciptive text
- **Assets** Array of Asset names that this ActiveScan policy should be applied to
- **ScanPolicy** Name of the ScanPolicy that should be applied to this ActiveScan
- **PolicyCredential** Array of policy credential names that should be used when running this ActiveScan
- **Reports** Array of report names that should be produced at the conclusion of the ActiveScans execution
- **Repository** Name of the repository that will be used for Asset and host lookup for this ActiveScan
- **Type** Type of ActiveScan to create.  Option are {"Plugin" | "Policy"}
- **Credential** PSCredential of a Tenable SecurityCenter user with rights to create the new ActiveScan

```PowerShell
xScActiveScan 'My_DSC_ActiveScan'
{
    Name             = 'MyDSCActiveScan'
    Ensure           = 'Present'
    ComputerName     = $ComputerName
    Credential       = $Credential
    Description      = 'DSC created active scan'
    Assets           = 'MyDscAsset'
    ScanPolicy       = 'MyDscScanPolicy'
    PolicyCredential = 'MyDscCredential'
    Reports          = 'Critical and Exploitable Vulnerabilities Report'
    Repository       = 'Default_Repository'
    Type             = 'policy'
    DependsOn        = @('[xScAsset]My_Dsc_Asset',
                         '[xScScanPolicy]My_Dsc_ScanPolicy',
                         '[xScCredential]PolicyCredential' )
}
```

### xScAsset

- **Name** Friendly name for the Asset we wish to create/modify/remove
- **Ensure** Specify whether the Asset should be present or removed
- **ComputerName** FQDN or IpAddress of the Tenable SecurityCenter server
- **Type** Specifies how a particular Asset will be identified.  Currently this module only supports the "Static" type. Full list of available options are: {"combination" | "dnsname" | "dnsnameupload" | "dynamic" | "ldapquery" | "static" | "staticeventfilter" | "staticvulnfilter" | "templates" | "upload" | "watchlist" | "watchlisteventfilter" | "watchlistupload"}
- **DefinedIps** Array of IpAddress that will be included in this asset group
- **Credential** PSCredential of a Tenable SecurityCenter user with rights to create the new Asset

```PowerShell
xScAsset 'My_Dsc_Asset'
{
    Name         = 'MyDscAsset'
    ComputerName = $ComputerName
    Credential   = $Credential
    Ensure       = 'Present'
    DefinedIps   = @('192.168.128.100', '192.168.128.45')
    Type         = 'static'
}
```

### xScAuditFile

- **Name** Friendly name for the AuditFile we wish to create/modify/remove
- **Ensure** Specify whether the AuditFile should be present or removed
- **ComputerName** FQDN or IpAddress of the Tenable SecurityCenter server
- **AuditFileTemplateName** Name of the AuditFileTemplate to base this new AuditFile off of
- **Credential** PSCredential of a Tenable SecurityCenter user with rights to create the new AuditFile

```PowerShell
xScAuditFile DISA_2012R2_MS_V2r215
{
    Name = "DISA_2012R2_MS_V2r215"
    AuditFileTemplateName = "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
    Ensure = "Present"
    ComputerName = $ComputerName
    Credential = $Credential
}
```
### xScCredential

- **Name** Friendly name for the PolicyCredential we wish to create/modify/remove
- **Ensure** Specify whether the PolicyCredential should be present or removed
- **ComputerName** FQDN or IpAddress of the Tenable SecurityCenter server
- **PolicyCredential** PSCredential object containing the UserName and Password you wish the new PolicyCredential to store
- **Credential** PSCredential of a Tenable SecurityCenter user with rights to create the new PolicyCredential

```PowerShell
xScCredential PolicyCredential
{
    Name = 'MyDscCredential'
    ComputerName = $ComputerName
    Credential = $Credential
    PolicyCredential = $policyCredential
    Ensure = 'Present'
}
```

### xScScanPolicy

- **Name** Friendly name for the ScanPolicy we wish to create/modify/remove
- **Ensure** Specify whether the ScanPolicyshould be present or removed
- **ComputerName** FQDN or IpAddress of the Tenable SecurityCenter server
- **PolicyTemplate** Friendly name of the ScanPolicy template we wish to base this new ScanPolicy off of
- **AuditFiles** Array of AuitFile names we wish to attach to this new ScanPolicy
- **Credential** PSCredential of a Tenable SecurityCenter user with rights to create the new ScanPolicy

```PowerShell
xScScanPolicy 'My_Dsc_ScanPolicy'
{
    Name = 'MyDscScanPolicy'
    ComputerName = $ComputerName
    Credential   = $Credential
    AuditFiles = @(
                    "MSCT_2012R2_MS_V1", 
                    "DISA_2012R2_MS_V2r215"
                    )
    PolicyTemplate = 'SCAP and OVAL Auditing'
    Ensure = 'Present'
    DependsOn = @("[xScCredential]PolicyCredential",
                  "[xScAuditFile]MSCT_2012R2_MS_V1",
                  "[xScAuditFile]DISA_2012R2_MS_V2r215")
}
```

