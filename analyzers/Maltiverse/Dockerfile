### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL author="ottimo" \
      description="Get the latest Maltiverse report for an hash, domain or an IP address." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Maltiverse" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Maltiverse

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Maltiverse/requirements.txt

ENTRYPOINT Maltiverse/maltiverse-client.py