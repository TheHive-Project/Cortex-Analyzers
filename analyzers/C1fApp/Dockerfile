### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="etz69" \
      description="Query C1fApp OSINT Aggregator for IPs, domains and URLs" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="C1fApp" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . C1fApp

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r C1fApp/requirements.txt

ENTRYPOINT C1fApp/cifquery.py