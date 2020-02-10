### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Eric Capuano" \
      description="Query AlienVault OTX for IPs, domains, URLs, or file hashes." \
      license="AGPL-V3" \
      title="OTXQuery" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . OTXQuery

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r OTXQuery/requirements.txt

ENTRYPOINT OTXQuery/otxquery.py