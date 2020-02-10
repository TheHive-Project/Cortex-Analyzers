### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Matt Erasmus, Jonas Hergenhahn" \
      description="Query haveibeenpwned.com for a compromised email address" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="HIBP" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . HIBP

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r HIBP/requirements.txt

ENTRYPOINT HIBP/hibpquery_analyzer.py