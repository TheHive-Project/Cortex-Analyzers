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

if ($expirationLength -le 0) {
    # No expiration
    New-TenantAllowBlockListItems -OutputJson -ListType Sender -Block -Notes $notes -Entries $entries -NoExpiration | ConvertTo-Json
} else {
    $expiry = (Get-Date).AddDays($expirationLength)
    New-TenantAllowBlockListItems -OutputJson -ListType Sender -Block -ExpirationDate $expiry -Notes $notes -Entries $entries | ConvertTo-Json
}
