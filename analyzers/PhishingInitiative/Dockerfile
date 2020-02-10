### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="Remi Pointel, CERT-BDF" \
      description="Use Phishing Initiative to check if a URL is a verified phishing site." \
      license="AGPL-V3" \
      title="PhishingInitiative" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . PhishingInitiative_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PhishingInitiative_Lookup/requirements.txt

ENTRYPOINT PhishingInitiative/phishinginitiative_lookup.py