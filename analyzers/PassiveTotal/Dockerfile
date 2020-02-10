### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="Brandon Dixon (9bplus), CERT-BDF" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="PassiveTotal" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . PassiveTotal

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PassiveTotal/requirements.txt

ENTRYPOINT PassiveTotal/passivetotal_analyzer.py