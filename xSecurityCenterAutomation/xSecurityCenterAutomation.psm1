Import-Module SecurityCenter -Force

enum Ensure
{
    Absent
    Present
}

[DscResource()]
class xScActiveScan
{
    [DscProperty(key)]
    [string]
    $Name

    [DscProperty(Mandatory)]
    [Ensure]
    $Ensure

    [DscProperty(Mandatory)]
    [string]
    $ComputerName

    [DscProperty(Mandatory = $false)]
    [string]
    $Description

    [DscProperty(Mandatory)]
    [String[]]
    $Assets

    [DscProperty(Mandatory)]
    [String]
    $ScanPolicy

    [DscProperty(Mandatory)]
    [String[]]
    $PolicyCredential

    [DscProperty(Mandatory)]
    [String[]]
    $reports

    [DscProperty(Mandatory)]
    [String]
    $Repository

    [DscProperty(Mandatory)]
    [String]
    $Type

    [DscProperty(Mandatory)]
    [PSCredential]
    $Credential

    [void] Set()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
            ErrorAction           = 'Stop'
        }

        $as = Get-ScActiveScan @params

        $params.Name = $this.ScanPolicy
        $p = Get-ScScanPolicy @params
        
        $params.Name = $this.Assets
        $a = Get-ScAsset @params

        $assetIds = @()
        foreach($obj in $a)
        {
            $assetIds += @{id = $obj.Id}
        }

        $params.Name = $this.PolicyCredential
        $pc = Get-ScPolicyCredential @params
        $policyCredIds = @()

        foreach($obj in $pc)
        {
            $policyCredIds += @{id = $obj.Id}
        }

        $params.Name = $this.reports
        $rpt = Get-ScReportDefinition @params
        $reportIds = @()

        foreach($obj in $rpt)
        {
            $reportIds += @{id = $obj.Id; reportSource = 'individual'}
        }

        $params.Name = $this.Repository
        $repo = Get-ScRepository @params

        if($this.Ensure -eq [Ensure]::Present)
        {
            if($as)
            {
                throw 'An active scan already exists by this name.'
            }

            $params = @{
                ComputerName          = $this.ComputerName
                Credential            = $this.Credential
                Name                  = $this.Name
                Description           = $this.Description
                Assets                = $assetIds
                ScanPolicyId          = @{id = $p.id}
                PolicyCredential      = $policyCredIds
                Reports               = $reportIds
                RepositoryId          = @{id = $repo.id}
                Type                  = $this.Type.ToLower()
            }
    
            New-ScActiveScan @params
        }
        else
        {
            if($this.Ensure -eq [Ensure]::Absent)
            {
                $params = @{
                    ComputerName          = $this.ComputerName
                    Credential            = $this.Credential
                    Name                  = $this.Name
                }

                Remove-ScActiveScan @params
            }   
        }
    }

    [bool] Test()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScActiveScan @params
        
        if($null -ne $present)
        {
            if($this.Ensure -eq [ensure]::Present)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        { 
            if($this.Ensure -eq [ensure]::Absent)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
    }

    [xScActiveScan] Get()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScActiveScan @params
        
        $this.Name = $present.Name
        
        return $this
    }

}

[DscResource()]
class xScAuditFile
{
    [DscProperty(key)]
    [string]
    $Name

    [DscProperty(Mandatory)]
    [Ensure]
    $Ensure

    [DscProperty(Mandatory)]
    [string]
    $ComputerName

    [DscProperty(Mandatory)]
    [string]
    $AuditFileTemplateName

    [DscProperty(Mandatory)]
    [PSCredential]
    $Credential

    [void] Set()
    {
        
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.AuditFileTemplateName
        }

        $aft = Get-ScAuditFileTemplate @params

        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $af = Get-ScAuditFile @params

        if($this.Ensure -eq [Ensure]::Present)
        {
            if($af)
            {
                throw 'An audit file already exists by this name utilizing a different audit file template.'
            }

            $params = @{
                ComputerName          = $this.ComputerName
                Credential            = $this.Credential
                Name                  = $this.Name
                AuditFileTemplateId   = @{id=$aft.id}
            }
    
            New-ScAuditFile @params
        }
        else
        {
            if($this.Ensure -eq [Ensure]::Absent)
            {
                $params = @{
                    ComputerName          = $this.ComputerName
                    Credential            = $this.Credential
                    Name                  = $this.Name
                }

                Remove-ScAuditFile @params
            }   
        }
        
    }

    [bool] Test()
    {
        
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScAuditFile @params

        if($present.auditFileTemplate.name -ne $this.AuditFileTemplateName)
        {
            $present = $null
        }
        
        if($null -ne $present)
        {
            if($this.Ensure -eq [ensure]::Present)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        { 
            if($this.Ensure -eq [ensure]::Absent)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
    }


    [xScAuditFile] Get()
    {
        
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScAuditFile @params

        $this.AuditFileTemplateName = $present.AuditFileTemplate.Name
        $this.Name = $present.Name
        
        return $this
       
    }
}

[DscResource()]
class xScCredential
{
    [DscProperty(key)]
    [string]
    $Name

    [DscProperty(Mandatory)]
    [Ensure]
    $Ensure

    [DscProperty(Mandatory)]
    [string]
    $ComputerName

    [DscProperty(Mandatory)]
    [PSCredential]
    $PolicyCredential

    [DscProperty(Mandatory)]
    [PSCredential]
    $Credential

    [void] Set()
    {
        
        $params = @{
                ComputerName          = $this.ComputerName
                Credential            = $this.Credential
                Name                  = $this.Name
        }

        $present = Get-ScPolicyCredential @params
        
        if($this.Ensure -eq [Ensure]::Present)
        {
            if($present)
            {
                throw 'A credential already exists by this name utilizing a different user account name.'
            }
        
            $params = @{
                ComputerName          = $this.ComputerName
                Credential            = $this.Credential
                PolicyCredential      = $this.PolicyCredential
                Name                  = $this.Name
            }

            New-ScPolicyCredential @params

        }
        else
        {
            if($present)
            {
                $params = @{
                    ComputerName          = $this.ComputerName
                    Credential            = $this.Credential
                    Name                  = $this.Name
                }

                Remove-ScPolicyCredential @params
            }
        }
    }

    [bool] Test()
    {
        
        $policyCredentialUserName = (Split-Path -Path $this.PolicyCredential.UserName -leaf)
        $policyCredentialDomainName = (Split-Path -Path $this.PolicyCredential.UserName -Parent)

        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScPolicyCredential @params

      
        if(($present.typefields.username -ne $policyCredentialUserName) -or
            $present.typefields.domain -ne $policyCredentialDomainName)
        {
            $present = $null
        }
        
        if($null -ne $present)
        {
            if($this.Ensure -eq [ensure]::Present)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        { 
            if($this.Ensure -eq [ensure]::Absent)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
}
    [xScCredential] Get()
    {      
        return $this
    }

    
}

[DscResource()]
class xScScanPolicy
{
    [DscProperty(key)]
    [string]
    $Name

    [DscProperty(Mandatory)]
    [Ensure]
    $Ensure

    [DscProperty(Mandatory)]
    [string]
    $ComputerName

    [DscProperty(Mandatory)]
    [String[]]
    $AuditFiles

    [DscProperty(Mandatory)]
    [string]
    $PolicyTemplate

    [DscProperty(Mandatory)]
    [PSCredential]
    $Credential

    [void] Set()
    {
        
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScScanPolicy @params

        if($this.Ensure -eq [Ensure]::Present)
        {
            if($present)
            {
                throw 'A policy already exists by this name utilizing a different Policy template.'
            }
            
            $af = Get-ScAuditFile -ComputerName $this.ComputerName -Credential $this.Credential -Name $this.AuditFiles
    
            $auditFileIds = @()

            foreach($file in $af)
            {
                $auditFileIds += @{id = $file.Id}
            }

            $pt = Get-ScScanPolicyTemplate -ComputerName $this.ComputerName -Credential $this.Credential -Name $this.PolicyTemplate

            $params = @{
                ComputerName = $this.ComputerName
                Credential = $this.Credential
                Name = $this.Name
                AuditFiles = $AuditFileIds
                PolicyTemplate = @{id = $pt.Id}
            }
            
            New-ScScanPolicy @params
        }
        else
        {
            if($present)
            {
                $params = @{
                    ComputerName          = $this.ComputerName
                    Credential            = $this.Credential
                    Name                  = $this.Name
                }

                Remove-ScScanPolicy @params
            }
        }

        

    }

    [bool] Test()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScScanPolicy @params

        $auditFilesPresent = $true

        foreach($af in $this.AuditFiles)
        {
            if($af -in $present.auditFiles.Name)
            {
                continue
            }
            else
            {
                $auditFilesPresent = $false
                break    
            }            
        }

        if((-not ($auditFilesPresent)) -or
            $present.policyTemplate.name -ne $this.PolicyTemplate)
        {
            $present = $null
        }
        
        if($null -ne $present)
        {
            if($this.Ensure -eq [ensure]::Present)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        { 
            if($this.Ensure -eq [ensure]::Absent)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
    }


    [xScScanPolicy] Get()
    {
        return $this
    }

}

[DscResource()]
class xScAsset
{
    [DscProperty(key)]
    [string]
    $Name

    [DscProperty(Mandatory)]
    [Ensure]
    $Ensure

    [DscProperty(Mandatory)]
    [string]
    $ComputerName

    [DscProperty(Mandatory)]
    [String[]]
    $DefinedIps

    [DscProperty(Mandatory)]
    [string]
    $Type

    [DscProperty(Mandatory)]
    [PSCredential]
    $Credential

    [void] Set()
    {
        
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScAsset @params

        if($this.Ensure -eq [Ensure]::Present)
        {
            if($present)
            {
                throw 'An asset already exists by this name.'
            }
            
            $params = @{
                ComputerName          = $this.ComputerName
                Credential            = $this.Credential
                Name                  = $this.Name
                type                  = $this.Type
                DefinedIps            = $this.DefinedIps
            }
            
            New-ScAsset @params
        }
        else
        {
            if($present)
            {
                $params = @{
                    ComputerName          = $this.ComputerName
                    Credential            = $this.Credential
                    Name                  = $this.Name
                }

                Remove-ScAsset @params
            }
        }

    }

    [bool] Test()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScAsset @params

        if($null -ne $present)
        {
            if($this.Ensure -eq [ensure]::Present)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        else
        { 
            if($this.Ensure -eq [ensure]::Absent)
            {
                return $true
            }
            else
            {
                return $false
            }
        }
    }


    [xScAsset] Get()
    {
        $params = @{
            ComputerName          = $this.ComputerName
            Credential            = $this.Credential
            Name                  = $this.Name
        }

        $present = Get-ScAuditFile @params
        $this.Name = $present.Name

        return $this
    }

}





