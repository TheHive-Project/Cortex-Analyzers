### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Use VirusTotal to scan a file or URL." \
      license="AGPL-V3" \
      title="VirusTotal" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . VirusTotal_Scan

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r VirusTotal_Scan/requirements.txt

ENTRYPOINT VirusTotal/virustotal.py