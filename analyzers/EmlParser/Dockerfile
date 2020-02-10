### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache g++ libmagic

LABEL author="ninsmith" \
      description="Parse Eml message" \
      license="AGPL-V3" \
      title="EmlParser" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.2.0"

WORKDIR /worker

COPY . EmlParser

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r EmlParser/requirements.txt

ENTRYPOINT EmlParser/parse.py