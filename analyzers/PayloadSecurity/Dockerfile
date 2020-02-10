### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Emmanuel Torquato" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="PayloadSecurity" \
      url="https://github.com/notset/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . PayloadSecurity_Url_Analysis

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PayloadSecurity_Url_Analysis/requirements.txt

ENTRYPOINT PayloadSecurity/payloadsecurity_analyzer.py