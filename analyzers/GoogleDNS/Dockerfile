### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-LaPoste" \
      description="Request Google DNS over HTTPS service" \
      license="AGPL-V3" \
      title="GoogleDNS" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . GoogleDNS_resolve

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleDNS_resolve/requirements.txt

ENTRYPOINT GoogleDNS/GoogleDNS_resolve.py