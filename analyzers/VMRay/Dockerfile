### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="VMRay Sandbox file analysis." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="VMRay" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . VMRay

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r VMRay/requirements.txt

ENTRYPOINT VMRay/vmray.py