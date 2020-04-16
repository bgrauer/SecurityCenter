#requires -Module 'Pester'
<#
    .SYNOPSIS
        Tests to validate the Operational funtionality of the module commands.  These
        test require an operational and licensed Nessus scanner and SecurityCenter server.
#>

Import-Module Pester
Import-Module -Name "$PSScriptRoot\..\SecurityCenter.psm1" -Force

Describe "SecurityCenter Operational Validation" {
    BeforeAll{
        $ComputerName = '192.168.128.191'
        $password = "!A@S3d4f5g6h7j8k"
        $script:AdminCreds = [pscredential]::new('admin', (ConvertTo-SecureString $password -AsPlainText -Force))
        $script:SecmanCreds = [pscredential]::new('secman', (ConvertTo-SecureString $password -AsPlainText -Force))
    
        $script:AuditFileTemplateName = "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"
        $script:AuditFileName = "PesterAuditFile"
        $script:scanPolicyName = "PesterScanPolicy"
        $script:PolicyCredentialName = 'PesterCredential'
        $script:ScanPolicyTemplateName = 'SCAP and OVAL Auditing'
        $script:AssetName = 'PesterDefinedAssets'
        $script:AssetIps = @('192.0.0.100', '192.0.0.200')
        $script:ReportDefinitionName = 'Critical and Exploitable Vulnerabilities Report'
        $script:RepositoryName = 'Default_Repository'
        $script:ActiveScanName = 'PesterCreatedActiveScan'

        $params = @{
            ComputerName = $ComputerName 
            Credential = $AdminCreds
        }

        function CleanUp($params){
    
            $params.Credential = $script:AdminCreds
            $params.Add('Name', $script:AuditFileName)
            if(Get-ScAuditFile @params){
                Remove-ScAuditFile @params
            }
            $params.Remove('Name')
            
            $params.Credential = $script:AdminCreds
            $params.Add('Name',$script:PolicyCredentialName)
            if(Get-ScPolicyCredential @params){
                Remove-ScPolicyCredential @params
            }
            $params.Remove('Name')

            $params.Credential = $script:AdminCreds
            $params.Add('Name', $script:ScanPolicyName)
            if(get-ScScanPolicy @params){
                Remove-ScScanPolicy @params
            }
            $params.Remove('Name')

            $params.Add('Name', $script:AssetName)
            $params.Credential = $script:SecmanCreds
            if(Get-ScAsset @params){
                Remove-ScAsset @params
            }
            $params.Remove('Name')

            $params.Add('Name', $Script:ActiveScanName)
            $params.Credential = $script:SecmanCreds
            if(Get-ScActiveScan @params){
                Remove-ScActiveScan @params
            }
            $params.Remove('Name')
        
        }
        
        CleanUp $params
    }

    AfterAll{
        Cleanup $params
    }

    Context 'Connect-SecurityCenter'{
        try{
            It 'Should return websession object'{
                $params.Add('IncludeWebSession', $true)

                $webSession = Connect-SecurityCenter @params
                $webSession | Should -Not -Be $null
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }
        finally{
            $params.Remove('IncludeWebSession')
        }
    }

    Context 'ScAuditFile'{
        try{
            It 'Should retrieve the specified audit file template'{
                $params.Credential = $script:AdminCreds
                $params.Add('Name', $script:auditFileTemplateName)
                $script:auditFileTemplate = Get-ScAuditFileTemplate @params
    
                $script:auditFileTemplate | Should -Not -Be $null
                $script:auditFileTemplate.name | Should -Be $script:AuditFileTemplateName
            }
        }
        catch{
           # Do nothing, let Pester handle this 
        }
        finally{
            $params.Remove('Name')
        }
        
        try{
            It 'Should create a new audit file'{
                $params.Credential = $script:AdminCreds
                $params.Add('Name', $script:AuditFileName)
                $params.Add('AuditFileTemplateId',(@{id = $script:auditFileTemplate.Id}))
                
                $af = New-ScAuditFile @params
                                
                $af | Should -Not -Be $null
                $af.Status | Should -Be 0
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }
        finally{
            $params.Remove('Name')
            $params.Remove('AuditFileTemplateId')
        }
        
    }

    Context 'ScPolicyCredential'{
        $CredentialPolicyName = 'PesterCredential'
        
        try{
            It 'Should create a new policy credential'{
                $params.Credential = $script:AdminCreds
                $params.Add('Name',$CredentialPolicyName)
                $params.Add('PolicyCredential', $SecmanCreds)
    
                $pc = New-ScPolicyCredential @params
    
                $pc | Should -Not -Be $null
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }        
        finally{
            $params.Remove('Name')
            $params.Remove('PolicyCredential')
        }

        try{
            It 'Should retrieve the specified policy'{
                $params.Credential = $script:AdminCreds
                $params.Add('Name',$CredentialPolicyName)
    
                $script:PolicyCredential = Get-ScPolicyCredential @params
    
                $script:PolicyCredential | Should -Not -Be $null
    
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }        
        finally{
            $params.Remove('Name')
        }
    }

    Context 'ScScanPolicyTemplate'{
        try{
            It 'Should return requested Scan Policy Template'{
                $params.Add('Name', $script:ScanPolicyTemplateName)
                $script:PolicyTemplate = Get-ScScanPolicyTemplate @params

                $script:PolicyTemplate | Should -Not -Be $null
                $script:PolicyTemplate.Name | Should -Be $script:ScanPolicyTemplateName
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }
        finally{
            $params.Remove('Name')
        }
    }

    Context 'ScScanPolicy'{
        try{
           $params.Add('Name', $script:AuditFileName) 

            $auditFiles = Get-ScAuditFile @params
            $script:auditFileIds = @()

            foreach($file in $AuditFiles){
                $script:auditFileIds += @{id = $file.Id}
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }
        finally{
            $params.Remove('Name')
        }
        
        try{
            It 'should create a new scan policy'{
                $params.Add('Name', $script:scanPolicyName)
                $params.Add('AuditFiles', $script:auditFileIds)
                $params.Add('PolicyTemplateId', (@{id = $script:PolicyTemplate.Id}))

                $scanPolicy = New-ScScanPolicy @params

                $scanPolicy | Should -Not -Be $null
            }
        }
        catch{

        }
        finally{
            $params.Remove('Name')
            $params.Remove('AuditFiles')
            $params.Remove('PolicyTemplateId')
        }

        try{
            It 'should return the requested scan policy' {
                $params.Add('Name', $script:scanPolicyName)

                $script:ScanPolicy = Get-ScScanPolicy @params

                $script:ScanPolicy | Should -Not -Be $null
            }
        }
        catch{
            throw $_
        }
        finally{
            $params.Remove('Name')
        }

    }

    Context 'ScAsset' {
        try{
            It 'should create a new asset' {
                $script:originalCreds = $params.Credential 
                $params.Credential = $Script:SecmanCreds
                $params.Add('Name', $script:AssetName)
                $params.Add('type', 'static')
                $params.Add('DefinedIps', $script:AssetIps)

                $a = New-ScAsset @params

                $a | Should -Not -Be $null

                foreach($ip in $script:AssetIps){
                    $a.TypeFields.DefinedIps -match $ip | Should -Be $true
                }
                
            }
        }
        catch{
            throw $_
        }
        finally{
            $params.Credential = $script:originalCreds
            $params.Remove('Name')
            $params.Remove('type')
            $params.Remove('DefinedIps')
        }

        try{
            It 'should retrieve the specified asset' {
                $script:originalCreds = $params.Credential 
                $params.Credential = $script:SecmanCreds
                $params.Add('Name', $script:AssetName)
                $script:assets = Get-ScAsset @params
                
                $script:assets | Should -Not -Be $null
                $script:assets.Name | Should -Be $script:AssetName
            }
        }
        catch{
            throw $_
        }
        finally{
            $params.Credential = $script:originalCreds
            $params.Remove('Name')
        }
    }
    
    Context 'ScReportDefinition'{
        try{
            It 'Should retrieve the specified report definition'{
                $params.Credential = $script:SecmanCreds
                $params.Add('Name',$script:ReportDefinitionName)
    
                $script:ReportDefinition = Get-ScReportDefinition @params
    
                $script:ReportDefinition | Should -Not -Be $null
    
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }        
        finally{
            $params.Remove('Name')
        }
    }

    Context 'ScRepository'{
        try{
            It 'Should retrieve the specified repository'{
                $params.Credential = $script:SecmanCreds
                $params.Add('Name',$script:RepositoryName)
    
                $script:Repository = Get-ScRepository @params
    
                $script:Repository | Should -Not -Be $null
    
            }
        }
        catch{
            # Do nothing, let Pester handle this
        }        
        finally{
            $params.Remove('Name')
        }
    }

    Context 'ScActiveScan'{
        try{
            It 'creates a new active scan'{
                $params.Credential = $script:SecmanCreds
                $params.Add('Name', $script:ActiveScanName)
                $params.Add('Description', 'Pester generated active scan')
                $params.Add('Assets', @{'id' = ($script:Assets).id})
                $params.Add('ScanPolicyId', @{'id' = ($script:ScanPolicy).id})
                $params.Add('PolicyCredential', @{'id' = ($script:policyCredential).id})
                $params.Add('Reports', @{'id' = $script:ReportDefinition.id; 'reportSource' = 'individual'})
                $params.Add('RepositoryId', @{'id' = $script:Repository.id})
                $params.Add('type', 'policy')

                $Script:ActiveScan = New-ScActiveScan @params

                $Script:ActiveScan | Should -Not -Be $null
                $script:ActiveScan.reports.name | Should -Be $script:ReportDefinitionName
                $script:ActiveScan.Assets.name | Should -Be $script:AssetName
                $script:ActiveScan.credentials.name | Should -Be $Script:PolicyCredentialName
                $script:ActiveScan.policy.name | Should -Be $script:scanPolicyName
            }
        }
        catch{
            throw $_
        }
        finally{
                $params.Remove('Name')
                $params.Remove('Description')
                $params.Remove('Assets')
                $params.Remove('ScanPolicyId')
                $params.Remove('PolicyCredential')
                $params.Remove('Reports')
                $params.Remove('RepositoryId')
                $params.Remove('type')
        }
    }
}
