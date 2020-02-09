### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="VirusTotal_Scan"
LABEL description="Use VirusTotal to scan a file or URL."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . VirusTotal_Scan

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r VirusTotal_Scan/requirements.txt

ENTRYPOINT VirusTotal/virustotal.py