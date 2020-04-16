<#
    .SYNOPSIS
        Connects to the SecurityCenter server and returns the web request session object

    .PARAMETER ComputerName
        IP address of SecurityCenter server

    .PARAMETER Credential
        Security Manager credential used to authenticate

    .PARAMETER IncludeWebSession
        Returns a websession object which includes cookie information which is
        required for the cmdlet Update-ScFeed.
#>

function Connect-SecurityCenter
{
    param
    (
        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $false)]
        [switch]
        $IncludeWebSession

    )

    # Logging into Linux server, props need to be lowercase
    $props = @{
        username = $Credential.UserName.ToLower()
        password = $Credential.GetNetworkCredential().Password
        releaseSession = 'False'
    }

    $Login = New-Object -TypeName PSCustomObject -Property $props

    $Data = (ConvertTo-Json -compress $Login)

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    # Login to Security Center
    $ret = Invoke-WebRequest -URI "https://$ComputerName/rest/token" -Method POST -Body $Data -UseBasicParsing -SessionVariable sv
    $token = (ConvertFrom-Json $ret.Content).response.token

    if ($IncludeWebSession)
    {
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $webSession.Credentials = $Credential

        $cookie = New-Object System.Net.Cookie
        $cookie.Name = "$($ret.BaseResponse.Cookies[0].Name)"
        $cookie.Value = "$($ret.BaseResponse.Cookies[0].Value)"
        $cookie.Domain = "$($ret.BaseResponse.Cookies[0].Domain)"

        $webSession.Cookies.Add($cookie)
    }

    return @{
        token = $token
        sv    = $sv
        WebSession = $WebSession
    }
}

<#
    .SYNOPSIS
        Retrieves SecurityCenter Report

    .PARAMETER ComputerName
        FQDN or IP address of SecurityCenter server

    .PARAMETER Credential
        SecurityCenter credential used to authenticate

    .PARAMETER ScanName
        Display Name in Security Manager of scan we want to launch

    .PARAMETER LogFileName
        Specified name you wish to save the scan as
#>

function Get-ScScanReport
{
    param
    (
        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(mandatory = $true)]
        [string]
        $ComputerName,

        [parameter(mandatory = $false)]
        [string]
        $DestinationPath,

        [parameter(mandatory = $false)]
        [string]
        $ScanId,

        [parameter(mandatory = $false)]
        [string]
        $ScanReportFileName
    )

    $outFile = "$DestinationPath\$ScanReportFileName"

    try
    {
        $session = Connect-SecurityCenter -ComputerName $computerName -Credential $Credential
        Invoke-WebRequest -URI " https://$ComputerName/rest/scanResult/$scanId/download" -UseBasicParsing -Headers @{"X-SecurityCenter" = "$($session.token)"} -Websession $($session.sv) -Method POST -OutFile $Outfile
        Write-Verbose -Message "Downloaded scan result id $scanId to $outFile"
    }
    catch
    {
        "Failed to download Scan Results: $($_.exception)"
    }
}

<#
    .SYNOPSIS
        Starts a predefined Nessus scan via Security Center

    .PARAMETER ComputerName
        IP address of the SecurityCenter server

    .PARAMETER Credential
        SecurityCenter credential used to authenticate

    .PARAMETER ScanName
        Display Name in Security Manager of scan we want to launch

    .PARAMETER MaxScanWaitTimeInMinutes
        The number of minutes we will attempt to determine the last scan's execution status
        before returning 'Status Unknown'
#>

function Start-ScScan
{
    param
    (
        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(mandatory = $true)]
        [string]
        $ComputerName,

        [parameter(mandatory = $true)]
        [string]
        $ScanName,

        [parameter(mandatory = $true)]
        [int]
        $MaxScanWaitTimeInMinutes
    )

    $session = Connect-SecurityCenter -ComputerName $ComputerName -Credential $Credential

    try
    {
        # get ScanID for ScanName provided
        $AllScans = ConvertFrom-Json (Invoke-WebRequest -URI " https://$ComputerName/rest/scan" -UseBasicParsing -Headers @{"X-SecurityCenter" = "$($session.token)"} -Websession $session.sv).Content
    }
    catch
    {
        throw $_
    }

    $Id = ($AllScans.response.usable | Where-Object -Property name -eq "$ScanName").Id

    try
    {
        $ret = ConvertFrom-Json (Invoke-WebRequest -URI " https://$ComputerName/rest/scan/$Id/launch" -UseBasicParsing -Headers @{"X-SecurityCenter" = "$($session.token)"} -Websession $session.sv -Method POST).Content
        $scanId = $ret.Response.ScanResult.Id
        $scanStatus = WaitForScanCompletion -MaxScanWaitTimeInMinutes $MaxScanWaitTimeInMinutes -id $ret.Response.ScanResult.Id
    }
    catch
    {
        throw $_
    }

    $props = @{
        Id = $scanId
        Status = $scanStatus
    }

    $ret = New-Object psobject -Property $props
    
    return $ret
}

<#
    .SYNOPSIS
        Wrapper used to generalize https REST calls to the Security Center API

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER ResourceName
        Security Center REST Api resource we wish to invoke.  A full list can be found at the following link.  Please note these are case sensitive.
        https://docs.tenable.com/sccv/api/index.html

    .PARAMETER Method
        HTTP method to invoke, valid options are 'Get' or 'Post'.

    .PARAMETER Data
        JSON API parameter data passed via the body of the http post.

    .PARAMETER Fields
        String of properties you wish the API to return if you required more than the defaults.

    .EXAMPLE
        Invoke-ScRestApi -ComputerName $ComputerName -Credential $credential -ResourceName 'asset' -Method 'Get' -Fields "name, id, type, groups"
#>

function Invoke-ScRestApi
{
    param
    (
        [parameter(mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $ResourceName,

        [parameter(Mandatory = $true)]
        [validateSet('Get', 'Post', 'Delete')]
        [string]
        $Method,

        [parameter(Mandatory = $false)]
        [psObject]
        $Data,

        [parameter(Mandatory = $false)]
        [string]
        $Fields,

        [parameter(Mandatory = $false)]
        [string]
        $Id,

        [parameter(Mandatory = $false)]
        [string[]]
        $Filter = $null
    )

    $session = Connect-SecurityCenter -ComputerName $ComputerName -Credential $Credential

    $params = @{
        Uri = "https://$computerName/rest/$resourceName"
        UseBasicParsing = $true
        Headers = @{'X-SecurityCenter' = $session.token}
        WebSession = $session.sv
        Method = $Method
    }

    if ($null -ne $Data)
    {
        $params.Add('Body', $data)
        $params.Method = 'Post'
    }

    if (-not([string]::IsNullOrEmpty($id)))
    {
        $params.Uri += "/$id"
    }

    if (-not([string]::IsNullOrEmpty($fields)))
    {
        $params.Uri += "?fields=$fields"
    }

    try
    {
        $ret = (Invoke-WebRequest @params | ConvertFrom-Json)
    }
    catch
    {
        throw
    }

    if (Get-Member -InputObject $ret.Response -MemberType Properties -Name 'usable')
    {
        $ret = $ret.Response.Usable
    }
    else
    {
        $ret = $ret.Response
    }

    if (-not ([string]::IsNullOrEmpty($filter)))
    {
        $tmp = @()

        foreach ($obj in $ret)
        {
            if ($filter -contains $obj.name)
            {
                $tmp += $obj
            }
        }

        $ret = $tmp
    }

    return $ret
}

<#
    .SYNOPSIS
        Get a list of all scanners defined in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the audit file to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScScanner
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'scanner'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
.SYNOPSIS
        Get a list of all scan zones defined in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the scan zone to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScScanZone
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'zone'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new scan zone in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Name for the new scan zone.

    .PARAMETER Description
         Specifies a description of the scan zone. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER IpList
        IpAddress or CIDR range of address that will be included in the scan zone.

    .PARAMETER ScannerId
        Id of the scanner that will be responsible for this zone.

    .EXAMPLE
        $scanner = Get-ScScanner -ComputerName $ComputerName -Credential $AdminCreds -Name 'Default_Scanner'

        New-ScScanZone -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewScanZone' -IpList @('192.0.0.0/24') -ScannerId @{id = $scanner.id}
#>

function New-ScScanZone
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $true)]
        [string]
        $IpList,

        [parameter(Mandatory = $true)]
        [hashtable]
        $ScannerId
    )

    $props = @{
        name = $name
        description = $description
        iplist = $IpList
        Scanners = $scannerId
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'zone'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of audit files configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the audit file to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScAuditFile
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'auditFile'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
        Fields       = 'id,name,description,type,status,auditFileTemplate'
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Removes the specified active scan from Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string, the display name of the active scan to be removed. 
#>

function Remove-ScActiveScan
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $activeScan = Get-ScActiveScan @params

    $params = @{
        ResourceName = 'scan'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id       = $activeScan.id
    }
   
    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Removes the specified audit file from Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string, the display name of the audit file to be removed. 
#>

function Remove-ScAuditFile
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $af = Get-ScAuditFile @params

    $params = @{
        ResourceName = 'auditFile'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id       = $af.id
    }
   
    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Removes the specified asset from Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string, the display name of the asset to be removed. 
#>

function Remove-ScAsset
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $a = Get-ScAsset @params

    $params = @{
        ResourceName = 'asset'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id       = $a.id
    }
   
    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}
<#
    .SYNOPSIS
        Returns a list of audit file templates configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the audit file template to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScAuditFileTemplate
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'auditFileTemplate'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new audit file in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Name for the new audit file.

    .PARAMETER Description
        Specifies a description of the audit file. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER AuditFileTemplateId
        The Id associated with the Audit file template to base the new audit file on.

    .EXAMPLE
        $auditFileTemplate = Get-ScAuditFileTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"

        New-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name "MyNewAuditFile" -AuditFileTemplateId @{id = $auditFileTemplate.Id}
#>

function New-ScAuditFile
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $true)]
        [Hashtable]
        $AuditFileTemplateId
    )

    $props = @{
        name = $name
        auditFileTemplate = $auditFileTemplateId
        description = $description
        status = '-1'
        variables = @(
            @{
                name = 'APP_USERS';
                value = 'app_users'
             },
             @{
                name = 'AUDITORS_GROUP' ;
                value = 'auditors'
             },
             @{
                name = 'NTP_SERVER';
                value = 'time\.windows\.com'
             }
        )
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'auditFile'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new Nessus scanner in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of the SecurityCenter administrative account that has rights to perform the desired action.

    .PARAMETER ScannerCredential
        Credentials of the Nessus administrative account that has rights to perform the desired action.

    .PARAMETER name
        Name for the new scanner.

    .PARAMETER description
        Specifies a description of the audit file. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER ScannerIp
        The Ip address of the Nessus server that will host this scanner

    .PARAMETER port
        TCP port used to communicate with Nessus on, 8834 is the default.

    .PARAMETER authType
        The method used to authenticate with Nessus.  Valid options are Password or SSL cert.

    .PARAMETER enabled
        Switch parameter indicating whether we want this scanner to be enabled or not.

    .PARAMETER agentCapable
        Switch parameter indicating whether we want this scanner to support agents.

    .PARAMETER zones
        Zones object of the scan zone this scanner should be attached to.  Run Get-ScScanZone to 
        retrieve this object.

    .EXAMPLE
        $auditFileTemplate = Get-ScAuditFileTemplate -ComputerName $ComputerName -Credential $AdminCreds -Name "DISA Windows Server 2012 and 2012 R2 MS STIG v2r15"

        New-ScAuditFile -ComputerName $ComputerName -Credential $AdminCreds -Name "MyNewAuditFile" -AuditFileTemplateId @{id = $auditFileTemplate.Id}
#>

function New-ScScanner
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,
        
        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $ScannerCredential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $false)]
        [string]
        $ScannerIp,

        [parameter(Mandatory = $false)]
        [string]
        $Port = '8834',

        [parameter(Mandatory = $false)]
        [string]
        $AuthType,

        [parameter(Mandatory = $false)]
        [switch]
        $Enabled,

        [parameter(Mandatory = $false)]
        [switch]
        $AgentCapable,

        [parameter(Mandatory = $true)]
        [Object]
        $Zones
    )

    $props = @{
        name = $name
        description = $description
        username = $scannerCreds.UserName
        password = $scannerCreds.GetNetworkCredential().Password
        ip = $ScannerIp
        port = $port
        authType = $authType
        enabled = 'false'
        agentCapable = 'false'
        nessusManagerOrgs = $null
        zones = @(
            @{
                id = $Scanzone.id
                ipList = $ScanZone.ipList
                modifiedTime = $Scanzone.modifiedTime
                name = $Scanzone.name
            }
        )
    }

    if($AgentCapable)
    {
        $props.agentCapable = 'true'
    }

    if($enabled)
    {
        $props.enabled = 'true'
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'scanner'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Removed the specified Nessus scanner from Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of the SecurityCenter administrative account that has rights to perform the desired action.

    .PARAMETER name
        Name of the scanner to be removed.

    .EXAMPLE
        Remove-ScScanner -ComputerName $ComputerName Credential $AdminCreds -Name "MyTestScanner"
#>

function Remove-ScScanner
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $s = Get-ScScanner @params

    $params = @{
        ResourceName = 'scanner'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id           = $s.Id
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new policy credential in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Name for the new credential.

    .PARAMETER Description
       Specifies a description of the credential. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER PolicyCredential
        A PowerShell pscredential object containing the account username and password values to be used.

    .EXAMPLE
        New-ScPolicyCredential -ComputerName $ComputerName -Credential $AdminCreds -Name 'MyNewCred' -PolicyCredential $DomainUserACreds
#>

function New-ScPolicyCredential
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $PolicyCredential
    )

    $domain = Split-Path $policyCredential.UserName -Parent
    $userName = Split-Path $policyCredential.UserName -Leaf

    $props = @{
        name = $name
        authType = 'password'
        description = $description
        domain = $domain
        type = 'windows'
        username = $userName
        password = $policyCredential.GetNetworkCredential().Password
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'credential'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of scan policies configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the asset to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScScanPolicy
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'policy'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
        Fields = "id,name,description,status,policyTemplate,auditFiles"
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of scan policy templates configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the asset to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScScanPolicyTemplate
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'policyTemplate'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new scan policy in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Name for the new audit file.

    .PARAMETER Description
        Specifies a description of the scan policy. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER AuditFileTemplateId
        The Id associated with the Audit file template to base the new audit file on.

    .EXAMPLE
        $template = (Get-ScScanPolicyTemplate -ComputerName $ComputerName -Credential $AdminCreds).response | where {$_.name -like "*SCAP*"}

        New-ScScanPolicy -ComputerName $ComputerName -Credential $AdminCreds -AuditFiles @({id = 1}) -PolicyTemplateId $template.id
#>

function New-ScScanPolicy
{

    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $true)]
        [Hashtable[]]
        $AuditFiles,

        [parameter(Mandatory = $true)]
        [Hashtable]
        $PolicyTemplateId
    )

    $props = @{
        name = $name
        description = $description
        auditFiles = $auditFiles
        policyTemplate = $policyTemplateId
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'policy'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of scans configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the scan to be retrieved. By default,
        this cmdlet gets all scans configured in Security Center.
#>

function Get-ScActiveScan
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'scan'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
        Fields       = 'id,name,description,type,status,policy'
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of groups configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the group to be retrieved. By default,
        this cmdlet gets all groups in Security Center.
#>

function Get-ScGroup
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'group'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
        Fields       = 'id,name,description,users'
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of assets configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the asset to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Get-ScAsset
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'asset'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
       Creates a new asset in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Name for the new assest resource.

    .PARAMETER Description
        Specifies a description of the asset. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER DefinedIps
        The IP ranges as specified by a string, string array or CIDR that will make up the resources
        included in this asset type.

    .PARAMETER Type
        The approached used to determine what nodes will be included in the asset.

    .EXAMPLE
       New-ScAsset -ComputerName $ComputerName -Credential $SecmanCreds -Name 'MyNewAsset' -DefinedIps '192.0.0.225' -type static
#>

function New-ScAsset
{

    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $true)]
        [string[]]
        $DefinedIps,

        [parameter(Mandatory = $true)]
        [ValidateSet("combination",
         "dnsname",
         "dnsnameupload",
         "dynamic",
         "ldapquery",
         "static",
         "staticeventfilter",
         "staticvulnfilter",
         "templates",
         "upload",
         "watchlist",
         "watchlisteventfilter",
         "watchlistupload")]
        [string]
        $type
    )

    $props = @{
        name = $name
        description = $description
        definedIPs = ($definedIps -join "`r `n")
        type = $type
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'asset'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of policy credentials configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the credential to be retrieved. By default,
        this cmdlet gets all credentials in Security Center.
#>

function Get-ScPolicyCredential
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'credential'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
        Fields = "id,name,description,type,typeFields"
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Deletes the specified policy credential from Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the credential to be Removed. 
#>

function Remove-ScPolicyCredential
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $policyCredential = Get-ScPolicyCredential @params
    
    $params = @{
        ResourceName = 'credential'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id           = $policyCredential.Id
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of scan policies configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the asset to be retrieved. By default,
        this cmdlet gets all assets in Security Center.
#>

function Remove-ScScanPolicy
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ComputerName          = $ComputerName
        Credential            = $Credential
        Name                  = $Name
    }

    $sp = Get-ScScanPolicy @params
    
    $params = @{
        ResourceName = 'policy'
        Method = 'Delete'
        Credential = $Credential
        ComputerName = $ComputerName
        Id           = $sp.Id
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of report definitions configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the report definition to be retrieved. By default,
        this cmdlet gets all report definitions in Security Center.
#>

function Get-ScReportDefinition
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'reportDefinition'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of repository configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the repository to be retrieved. By default,
        this cmdlet gets all repositories in Security Center.
#>

function Get-ScRepository
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name
    )

    $params = @{
        ResourceName = 'repository'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Returns a list of plugins configured in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the plugin to be retrieved. By default,
        this cmdlet gets all plugins in Security Center.

    .PARAMETER Id
        Specifieds, as a string, the id of the plugin to be retrieved.
#>

function Get-ScPlugin
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $false)]
        [string[]]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Id
    )

    $params = @{
        ResourceName = 'plugin'
        Method = 'Get'
        Credential = $Credential
        ComputerName = $ComputerName
    }

    if(-not ([string]::IsNullOrEmpty($name)))
    {
        $params.Add('Filter', $Name)
    }

    if(-not ([string]::IsNullOrEmpty($id)))
    {
        $params.Add('Id', $id)
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Creates a new active scan in Security Center.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Name
        Specifies, as a string array, the display names of the plugin to be retrieved. By default,
        this cmdlet gets all plugins in Security Center.

    .PARAMETER Description
        Specifies a description of the scan. You can type any string. If the description includes spaces, enclose it in quotation marks.

    .PARAMETER Assets
        Array of hashtables that includes an Id property and the id of the asset you wish to include with the scan.

    .PARAMETER IpList
        Ip address of the machine to be scanned.  Useful for ad-hoc scanning needs. Can NOT be used in conjunction with 
        the 'Assets' parameter.

    .PARAMETER ScanPolicyId
        A hashtable that includes an Id property and the id of the scan policy to apply to this scan.

    .PARAMETER PolicyCredential
        Array of hashtables that includes an Id property and the id of the credential you wish to include with the scan.

    .PARAMETER Reports
        Array of hashtables that includes an Id property and the id of the report you wish to include with the scan.

    .PARAMETER RepositoryId
        A hashtable that includes an Id property and the id of the repository to include with this scan.

    .PARAMETER Type
        The type of scan to be created.  Valid options are 'policy' or 'plugin' (CASE SENSITIVE)

    .EXAMPLE
        $params = @{
            ComputerName = $ComputerName
            Credential = $SecmanCreds
            Name = 'MyNewScan'
            Description = 'Powershell ROCKS!'
            Assets = $assetIds
            ScanPolicyId = @{id = $Policy.Id}
            PolicyCredential = @(@{id = $policyCreds[0].Id},@{id = $policyCreds[1].Id})
            Reports = @(@{id = $reports.id; reportSource = 'individual'})
            RepositoryId = @{id = $repository.id}
            type = 'policy'
        }

        New-ScActiveScan @params
#>

function New-ScActiveScan
{
param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Name,

        [parameter(Mandatory = $false)]
        [string]
        $Description,

        [parameter(Mandatory = $false)]
        [Hashtable[]]
        $Assets,

        [parameter(Mandatory = $false)]
        [string]
        $IpList,

        [parameter(Mandatory = $false)]
        [Hashtable]
        $ScanPolicyId,

        [parameter(Mandatory = $true)]
        [Hashtable[]]
        $PolicyCredential,

        [parameter(Mandatory = $true)]
        [Hashtable[]]
        $Reports,

        [parameter(Mandatory = $false)]
        [Hashtable]
        $RepositoryId,

        [parameter(Mandatory = $true)]
        [ValidateSet("plugIn", "policy")]
        [string]
        $type
    )

    $props = @{
        name = $name
        description = $description
        policy = $scanPolicyId
        credentials = $policyCredential
        reports = $reports
        repository = $repositoryId
        type = $type
    }

    if($null -ne $Assets)
    {
        $props.add('assets', $assets)
    }

    if($null -ne $IpList)
    {
        $props.add('ipList', $IpList)
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        ResourceName = 'scan'
        Method = 'Post'
        Data = $data
        Credential = $Credential
        ComputerName = $ComputerName
    }

    try
    {
        $ret = Invoke-ScRestApi @params
    }
    catch
    {
        throw
    }

    return $ret
}

<#
    .SYNOPSIS
        Uploads and commits a SecurityCenter plug-in feed file.

    .PARAMETER ComputerName
        NetBios or Ip address of the Security Center application server.

    .PARAMETER Credential
        Credentials of user account that has rights to perform the desired action.

    .PARAMETER Path
        Path to the feed file to be uploaded.

    .PARAMETER Type
        Plug-in type of the feed file.  Valid options are 'active', 'passive', 'lce' or 'sc'
#>

function Update-ScFeed
{
    param
    (
        [parameter(Mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(Mandatory = $true)]
        [string]
        $Path,

        [parameter(Mandatory = $true)]
        [ValidateSet("active", "passive", "lce", "sc")]
        [string]
        $Type
    )

    $boundary = [Guid]::NewGuid().ToString()
    $LF = "`r`n";

    $bodystart = @"
--$boundary
Content-Disposition: form-data; name="Filedata"; filename="$((Split-Path -Path $Path -Leaf))"
Content-Type: application/x-gzip
"@

    $bodyEnd = @"
$LF--$boundary--
"@

    $requestInFile = (Join-Path -Path $env:TEMP -ChildPath ([IO.Path]::GetRandomFileName()))

    # Create a new object for the brand new temporary file
    $fileStream = (New-Object -TypeName 'System.IO.FileStream' -ArgumentList ($requestInFile, [IO.FileMode]'Create', [IO.FileAccess]'Write'))

    try
    {
        # The Body start
        $bytes = [Text.Encoding]::UTF8.GetBytes($bodyStart)
        $fileStream.Write($bytes, 0, $bytes.Length)

        # The original File
        $bytes = [IO.File]::ReadAllBytes($Path)
        $fileStream.Write($bytes, 0, $bytes.Length)

        # Append the end of the body part
        $bytes = [Text.Encoding]::UTF8.GetBytes($bodyEnd)
        $fileStream.Write($bytes, 0, $bytes.Length)
    }
    finally
    {
        # End the Stream to close the file
        $fileStream.Close()

        # Cleanup
        $fileStream = $null

        # PowerShell garbage collector
        [GC]::Collect()
    }

    $contentType = 'multipart/form-data; boundary={0}' -f $boundary

    $session = Connect-SecurityCenter -ComputerName $computerName -Credential $AdminCreds -IncludeWebSession

    $params = @{
        Uri = "https://$ComputerName/rest/file/upload"
        Method = 'Post'
        ContentType = $contentType
        InFile = $requestInFile
        Headers = @{
            "X-SecurityCenter" = "$($session.token)";
            "Accept-Encoding"="gzip, deflate";
            "accept" = "application/json, text/javascript, */*; q=0.01"
        }
        WebSession = $session.WebSession

    }

    $ret = Invoke-RestMethod @params

    $props = @{
        filename = $ret.response.filename
    }

    $data = (New-Object -TypeName PSCustomObject -Property $props) | ConvertTo-Json -Compress

    $params = @{
        Uri = "https://$ComputerName/rest/feed/$type/process"
        Method = 'Post'
        Headers = @{
            "X-SecurityCenter" = "$($session.token)";
            "Accept-Encoding"="gzip, deflate";
            "accept" = "application/json, text/javascript, */*; q=0.01"
        }
        Body = $data
        WebSession = $session.WebSession

    }

    $ret = Invoke-RestMethod @params

    return $ret
}

<#
    .SYNOPSIS
        Returns the most recent scan result status of the specified scan

    .PARAMETER ComputerName
        IP address of SecurityCenter server

    .PARAMETER Credential
        SecurityCenter credential used to authenticate

    .PARAMETER Id
        Id of the scan result we wish to retrieve the status of
#>

function Get-ScScanStatus
{
    param
    (
        [parameter(Mandatory = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(mandatory = $true)]
        [String]
        $ComputerName,

        [parameter(mandatory = $true)]
        [Int]
        $Id
    )

    $session = Connect-SecurityCenter -ComputerName $ComputerName -Credential $Credential

    try
    {
        # get ScanID for ScanName provided
        $AllScans = ConvertFrom-Json (Invoke-WebRequest -URI " https://$ComputerName/rest/scanResult" -UseBasicParsing -Headers @{"X-SecurityCenter" = "$($session.token)"} -Websession $session.sv).Content

        # loop through all scans looking for correct scan id.  Starting at end as this is where the scan 'should' be
        for ($i = ($AllScans.Response.Usable.count - 1); $i -ge 0; $i--)
        {
            if ($AllScans.Response.Usable[$i].id -eq $Id)
            {
                $ret = $AllScans.Response.Usable[$i].status
                break
            }
        }
    }
    catch
    {
        throw $_
    }

    return $ret
}

<#
    .SYNOPSIS
        Polls status of specified scan result and returns when scan has completed or failed, or
        the maximum scan time has exceeded

    .PARAMETER MaxScanTimeInMinutes
        The time in minutes that the function will poll the specified scan waiting on
        it to either complete or fail.

    .PARAMETER Id
        The scan result Id that we want to retrieve the status of
#>

function WaitForScanCompletion
{
    param
    (
        [parameter(mandatory = $true)]
        [string]
        $MaxScanWaitTimeInMinutes,

        [parameter(mandatory = $true)]
        [int]
        $Id
    )

    # need to call AddMinutes from variable so we could Mock Get-Date correctly for unit testing
    $maxWaitTime = Get-Date
    $maxWaitTime = $maxWaitTime.AddMinutes($MaxScanWaitTimeInMinutes)

    do
    {
        $scanStatus = Get-ScScanStatus -Credential $Credential -ComputerName $ComputerName -Id $Id

        start-sleep -Seconds 5
    }
    while (($(Get-Date -DisplayHint 'DateTime') -lt $maxWaitTime) -and (($scanStatus -ne 'Completed') -and ($scanStatus -ne 'Error')))

    if (($scanStatus -eq 'Completed') -or ($scanStatus -eq 'Error'))
    {
        $ret = $scanStatus
    }
    else
    {
        $ret = 'Status Unknown'
    }

    return $ret
}
