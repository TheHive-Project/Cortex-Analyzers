### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Get the Hippocampe detailed report for an IP address, a domain or a URL." \
      license="AGPL-V3" \
      title="Hippocampe" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . HippoMore

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r HippoMore/requirements.txt

ENTRYPOINT Hippocampe/hippo.py