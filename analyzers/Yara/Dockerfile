### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache gcc musl-dev

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check files against YARA rules." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Yara" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . Yara

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Yara/requirements.txt

ENTRYPOINT Yara/yara_analyzer.py