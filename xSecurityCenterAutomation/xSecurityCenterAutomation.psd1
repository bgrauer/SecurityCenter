@{

# Script module or binary module file associated with this manifest.
RootModule = 'xSecurityCenter.psm1'

DscResourcesToExport = 'xScAuditFile',
                       'xScCredential',
                       'xScScanPolicy',
                       'xScAsset', 
                       'xScActiveScan'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '298b4d5b-be0b-45f7-a88c-ea5d2ee7c27a'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) 2014 Microsoft. All rights reserved.'

# Description of the functionality provided by this module
# Description = ''

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''
}