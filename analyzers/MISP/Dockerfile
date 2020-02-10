### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Query multiple MISP instances for events containing an observable." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="MISP" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.1.0"

WORKDIR /worker

COPY . MISP

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MISP/requirements.txt

ENTRYPOINT MISP/misp.py