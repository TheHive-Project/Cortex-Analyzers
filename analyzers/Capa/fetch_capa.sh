#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status
set -x  # Print commands and their arguments as they are executed

# Fetch the latest release version
LATEST_VERSION=$(curl -s https://api.github.com/repos/mandiant/capa/releases/latest | jq -r '.tag_name')

# Validate the version
if [ -z "$LATEST_VERSION" ]; then
    echo "Failed to fetch the latest version."
    exit 1
fi

echo "Latest version is $LATEST_VERSION"

# Construct the download URL
DOWNLOAD_URL="https://github.com/mandiant/capa/releases/download/${LATEST_VERSION}/capa-${LATEST_VERSION}-linux.zip"
echo "Downloading from $DOWNLOAD_URL"

# Download and extract capa
curl -L -o capa.zip "$DOWNLOAD_URL" || { echo "Download failed"; exit 1; }
unzip capa.zip -d /worker/capa || { echo "Extraction failed"; exit 1; }

# Clean up
rm capa.zip
echo "Capa downloaded and extracted successfully."
