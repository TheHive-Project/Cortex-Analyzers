param (
    [parameter(mandatory=$true)]
    [string] $certFilePath,
    [parameter(mandatory=$true)]
    [string] $certPassword,
    [parameter(mandatory=$true)]
    [string] $appId,
    [parameter(mandatory=$true)]
    [string] $organization,
    [parameter(mandatory=$true)]
    [string] $listType,
    [parameter(mandatory=$true, valueFromRemainingArguments=$true)]
    [string[]] $entries
)

$connectSplat = @{
    CertificateFilePath = $certFilePath
    CertificatePassword = $(ConvertTo-SecureString -String $certPassword -AsPlainText -Force)
    AppId = $appId
    Organization = $organization
}

Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
Connect-ExchangeOnline @connectSplat

$allResults = @()
ForEach ($entry in $entries) {
    $result = Remove-TenantAllowBlockListItems -ListType $listType -Entries $entry | ConvertTo-Json
    $allResults += @{
        entry = $entry;
        result = $result;
        error = If ($?) {$null} else {$Error[0].Exception.SerializedRemoteException.Message};
    }
}

$allResults | ConvertTo-Json -Depth 4
