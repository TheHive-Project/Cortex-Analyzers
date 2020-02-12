### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Fetch observable details from a YETI instance." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Yeti" \
      url="https://github.com/CERT/cortex-analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Yeti

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Yeti/requirements.txt

ENTRYPOINT Yeti/yeti.py