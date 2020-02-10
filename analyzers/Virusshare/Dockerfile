### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Search for MD5 hashes in Virusshare.com hash list" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Virusshare" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . Virusshare

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Virusshare/requirements.txt

ENTRYPOINT Virusshare/virusshare.py