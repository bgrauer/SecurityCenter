#region Common Variables

$ComputerName = 'SecurityCenterIpAddress'
$password = "SomePassword"
$AdminCreds = [pscredential]::new('admin', (ConvertTo-SecureString $password -AsPlainText -Force))
$SecmanCreds = [pscredential]::new('secman', (ConvertTo-SecureString $password -AsPlainText -Force))

Import-Module -Name "$PSScriptRoot\..\SecurityCenter\SecurityCenter.psm1" -Force
break
#endregion

#region Connection

Connect-SecurityCenter -ComputerName $ComputerName -Credential $AdminCreds

#endregion

#region Update-ScFeed

Update-scFeed -ComputerName $ComputerName -Credential $AdminCreds -Path C:\lab\CM-239615-SecurityCenterFeed48.tar.gz -Type sc

#endregion

#region New-ScAuditFile

$auditFileTemplate = Get-ScAuditFileTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
New-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name "MyNewAuditFile" -AuditFileTemplateId @{id = $auditFileTemplate.Id}

#endregion

#region New-ScPolicyCredential 

New-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewAdminCred' -PolicyCredential $AdminCreds
Get-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds

#endregion

#region New-ScScanPolicy

$auditFiles = Get-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewAuditFile', 'SomeOtherAuditFile'
$auditFileIds = @()
foreach($file in $AuditFiles)
{
    $auditFileIds += @{id = $file.Id}
}

$policyTemplate = Get-ScScanPolicyTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name 'SCAP and OVAL Auditing'
New-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewScanPolicy' -AuditFiles $AuditFileIds -PolicyTemplateId @{id = $policyTemplate.Id} 

#endregion

#region New-ScAsset

New-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds -Name 'MySqlServers' -type 'static' -DefinedIps @('192.0.0.100', '192.0.0.200')

#endregion

#region New-ScActiveScan

$assets = Get-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds -name 'MySqlServers' 
$assetIds = @()
foreach($obj in $assets)
{
    $assetIds += @{id = $obj.Id}
}

$policyCreds = Get-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds -Name 'DomainX\SqlAdmin1', 'DomainX\SqlAdmin2'
$policyCredIds = @()
foreach($obj in $policyCreds)
{
    $policyCredIds += @{id = $obj.Id}
}

$policy = Get-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewScanPolicy'

$reports = Get-ScReportDefinition -ComputerName $ComputerName -Credential $SecmanCreds -Name 'Critical and Exploitable Vulnerabilities Report'
$repository = Get-ScRepository -ComputerName $ComputerName -Credential $AdminCreds -Name 'Default_Repository'

$params = @{
    ComputerName = $ComputerName
    Credential = $SecmanCreds
    Name = 'MyNewScanPolicy'
    Description = 'Powershell ROCKS!'
    Assets = $assetIds
    ScanPolicyId = @{id = $Policy.Id}
    PolicyCredential = @(@{id = $policyCreds[0].Id},@{id = $policyCreds[1].Id})
    Reports = @(@{id = $reports.id; reportSource = 'individual'})
    RepositoryId = @{id = $repository.id}
    type = 'policy'
}

New-ScActiveScan @params

Start-ScScan -ComputerName $ComputerName -Credential $SecmanCreds -ScanName 'MyNewScanPolicy' -MaxScanWaitTimeInMinutes 5

#endregion