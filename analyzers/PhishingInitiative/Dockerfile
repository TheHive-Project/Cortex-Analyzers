### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="CERT-BDF, Remi Pointel" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="PhishingInitiative" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . PhishingInitiative

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PhishingInitiative/requirements.txt

ENTRYPOINT PhishingInitiative/phishinginitiative_lookup.py