### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache gcc git musl-dev

LABEL author="ANSSI" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="AutoFocus" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . AutoFocus

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r AutoFocus/requirements.txt

ENTRYPOINT AutoFocus/analyzer.py