FROM python:3-alpine

# See : https://learn.microsoft.com/en-us/powershell/scripting/install/install-alpine?view=powershell-7.5

# Install base dependencies
RUN apk add --no-cache \
    ca-certificates \
    less \
    ncurses-terminfo-base \
    krb5-libs \
    libgcc \
    libintl \
    libssl3 \
    libstdc++ \
    tzdata \
    userspace-rcu \
    zlib \
    icu-libs \
    curl

# Install additional packages from Alpine edge main repository
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
    lttng-ust \
    openssh-client

# Download the PowerShell .tar.gz archive
RUN curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-musl-x64.tar.gz -o /tmp/powershell.tar.gz

# Create the target folder where PowerShell will be placed
RUN mkdir -p /opt/microsoft/powershell/7

# Extract PowerShell into the target folder
RUN tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7

# Set execute permissions on the PowerShell binary
RUN chmod +x /opt/microsoft/powershell/7/pwsh

# Create a symbolic link to pwsh in /usr/bin for easy access
RUN ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh

WORKDIR /worker

# Copy the requirements for MSDefenderOffice365 and install them
COPY requirements.txt MSDefenderOffice365/
RUN pip3 install --no-cache-dir -r MSDefenderOffice365/requirements.txt

# Copy the rest of the analyzer code into the MSDefenderOffice365 folder
COPY . MSDefenderOffice365/

# Set the entrypoint using JSON array syntax for proper OS signal handling
ENTRYPOINT ["python3", "MSDefenderOffice365/ms_defender_office.py"]
