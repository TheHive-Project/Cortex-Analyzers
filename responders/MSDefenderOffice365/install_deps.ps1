Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name PSWSMan -Scope AllUsers -RequiredVersion 2.3.0
Install-WSMan
