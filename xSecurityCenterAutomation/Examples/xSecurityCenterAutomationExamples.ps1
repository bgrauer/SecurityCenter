Set-Location C:\dsc\SecurityCenter
$SecManUserName = "Secman"
$SecManPassword = "SomePassword"
$SecManCredentials = New-Object System.Management.Automation.PSCredential($SecManUsername, (ConvertTo-SecureString $SecManPassword -AsPlainText -Force))

$policyCredentialUserName = 'DomainX\User1'
$policyCredentialPassword = "SomePassword"
$policyCredential = New-Object System.Management.Automation.PSCredential($policyCredentialUserName, (ConvertTo-SecureString $policyCredentialPassword -AsPlainText -Force))

$ComputerName = 'FQDN | IpAddress'

break

Configuration ScDscExamplePresent
{
    param
    (
        [pscredential]
        $Credential,
        
        [pscredential]
        $PolicyCredential,
        
        [string]
        $ComputerName          
    )
    
    Import-DSCResource -Module xSecurityCenter 
                    
    Node $AllNodes.nodename
    {
        LocalConfigurationManager
        {
            CertificateId = $node.Thumbprint
        }

        xScAuditFile DISA_2012R2_MS_V2r215
        {
            Name = "DISA_2012R2_MS_V2r215"
            AuditFileTemplateName = "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
            Ensure = "Present"
            ComputerName = $ComputerName
            Credential = $Credential
        }

        xScAuditFile MSCT_2012R2_MS_V1
        {
            Name = "MSCT_2012R2_MS_V1"
            AuditFileTemplateName = "MSCT Windows Server 2012 R2 MS v1.0.0"
            Ensure = "Present"
            ComputerName = $ComputerName
            Credential = $Credential
        }

        xScCredential PolicyCredential
        {
            Name = 'MyDscCredential'
            ComputerName = $ComputerName
            Credential = $Credential
            PolicyCredential = $policyCredential
            Ensure = 'Present'
        }

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

        xScAsset 'My_Dsc_Asset'
        {
            Name         = 'MyDscAsset'
            ComputerName = $ComputerName
            Credential   = $Credential
            Ensure       = 'Present'
            DefinedIps   = @('192.168.128.100', '192.168.128.45')
            Type         = 'static'
            DependsOn = '[xScScanPolicy]My_Dsc_ScanPolicy'
        }
        
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
            DependsOn        = '[xScAsset]My_Dsc_Asset'
        }
    }
}

Configuration ScDscExampleAbsent
{
    param
    (
        [pscredential]
        $Credential,
        
        [pscredential]
        $PolicyCredential,
        
        [string]
        $ComputerName          
    )
    
    Import-DSCResource -module xSecurityCenter
            
    Node $AllNodes.nodename
    {
        LocalConfigurationManager
        {
            CertificateId = $node.Thumbprint
        }

        xScAuditFile DISA_2012R2_MS_V2r215
        {
            Name = "DISA_2012R2_MS_V2r215"
            AuditFileTemplateName = "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
            Ensure = "Absent"
            ComputerName = $ComputerName
            Credential = $Credential
            DependsOn = "[xScScanPolicy]Rvp_Scan"
        }

        xScAuditFile MSCT_2012R2_MS_V1
        {
            Name = "MSCT_2012R2_MS_V1"
            AuditFileTemplateName = "MSCT Windows Server 2012 R2 MS v1.0.0"
            Ensure = "Absent"
            ComputerName = $ComputerName
            Credential = $Credential
            DependsOn = "[xScScanPolicy]Rvp_Scan"
        }

        xScCredential PolicyCredential
        {
            Name = 'MyDscCredential'
            ComputerName = $ComputerName
            Credential = $Credential
            PolicyCredential = $policyCredential
            Ensure = 'Absent'
        }

        xScScanPolicy Rvp_Scan
        {
            Name = 'Rvp_Scan'
            ComputerName = $ComputerName
            Credential   = $Credential
            AuditFiles = @(
                            "MSCT_2012R2_MS_V1", 
                            "DISA_2012R2_MS_V2r215"
                          )
            PolicyTemplate = 'SCAP and OVAL Auditing'
            Ensure = 'Absent'
        }

        
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
            Ensure = 'absent'
            DependsOn = @("[xScCredential]PolicyCredential",
                          "[xScAuditFile]MSCT_2012R2_MS_V1",
                          "[xScAuditFile]DISA_2012R2_MS_V2r215")
        }


        xScAsset 'My_Dsc_Asset'
        {
            Name         = 'MyDscAsset'
            ComputerName = $ComputerName
            Credential   = $Credential
            Ensure       = 'absent'
            DefinedIps   = @('192.168.128.100', '192.168.128.45')
            Type         = 'static'
            DependsOn = '[xScScanPolicy]My_Dsc_ScanPolicy'
        }
        
        xScActiveScan 'My_DSC_ActiveScan'
        {
            Name             = 'MyDSCActiveScan'
            Ensure           = 'absent'
            ComputerName     = $ComputerName
            Credential       = $Credential
            Description      = 'DSC created active scan'
            Assets           = 'MyDscAsset'
            ScanPolicy       = 'MyDscScanPolicy'
            PolicyCredential = 'MyDscCredential'
            Reports          = 'Critical and Exploitable Vulnerabilities Report'
            Repository       = 'Default_Repository'
            Type             = 'policy'
            DependsOn        = '[xScAsset]My_Dsc_Asset'
        }
    }
    }


$cd = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PSDscAllowPlainTextPassword = $false
            CertificateFile = "c:\temp\DscPublicKey.cer"
            Thumbprint = '92995D2BEEA02AE0F6BDAF298A953473FCD0A1E1'
        }
    )
}

ScDscExamplePresent -ComputerName $ComputerName -Credential $SecManCredentials -PolicyCredential $policyCredential -ConfigurationData $cd

ScDscExampleAbsent -ComputerName $ComputerName -Credential $SecManCredentials -PolicyCredential $policyCredential -ConfigurationData $cd
# Set-DscLocalConfigurationManager ScDscExamplePresent -force


Start-DscConfiguration -Wait -verbose -Force ScDscExamplePresent

Start-DscConfiguration -Wait -Force ScDscExampleAbsent