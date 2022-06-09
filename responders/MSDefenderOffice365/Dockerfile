FROM python:3.10-slim

# Install system components
RUN apt-get update  && apt-get install -y curl gnupg apt-transport-https

# Import the public repository GPG keys
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

# Register the Microsoft Product feed
RUN sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'

# Install PowerShell (/usr/bin/pwsh)
RUN apt-get update && apt-get install -y powershell

# RUN pwsh -c "Install-Module -Name ExchangePowerShell -Force"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -Force"

WORKDIR /worker
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python3", "ms_defender_office.py"]
