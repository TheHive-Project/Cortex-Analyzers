### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Use Google Safebrowing to check URLs and domain names." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="GoogleSafebrowsing" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . GoogleSafebrowsing

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleSafebrowsing/requirements.txt

ENTRYPOINT GoogleSafebrowsing/safebrowsing_analyzer.py