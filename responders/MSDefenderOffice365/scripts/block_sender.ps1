param (
    [parameter(mandatory=$true)]
    [string] $certFilePath,
    [parameter(mandatory=$true)]
    [string] $certPassword,
    [parameter(mandatory=$true)]
    [string] $appId,
    [parameter(mandatory=$true)]
    [string] $organization,
    [string] $notes="",
    [parameter(mandatory=$true)]
    [int] $expirationLength,
    [parameter(mandatory=$true, valueFromRemainingArguments=$true)]
    [string[]] $entries
)

$connectSplat = @{
    CertificateFilePath = $certFilePath
    CertificatePassword = $(ConvertTo-SecureString -String $certPassword -AsPlainText -Force)
    AppId = $appId
    Organization = $organization
}

Connect-ExchangeOnline @connectSplat

$allResults = @()
ForEach ($entry in $entries) {
    if ($expirationLength -le 0) {
        # No expiration
        $result = New-TenantAllowBlockListItems -ListType Sender -Block -Notes $notes -Entries $entry -NoExpiration -ErrorAction Continue | ConvertTo-Json
        $allResults += @{
            entry = $entry;
            result = $result;
            error = If ($?) {$null} else {$Error[0].Exception.SerializedRemoteException.Message};
        }
    } else {
        $expiry = (Get-Date).AddDays($expirationLength)
        $result = New-TenantAllowBlockListItems -ListType Sender -Block -ExpirationDate $expiry -Notes $notes -Entries $entry -ErrorAction Continue | ConvertTo-Json
        $allResults += @{
            entry = $entry;
            result = $result;
            error = If ($?) {$null} else {$Error[0].Exception.SerializedRemoteException.Message};
        }
    }
}

$allResults | ConvertTo-Json -Depth 4
