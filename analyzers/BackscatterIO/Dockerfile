### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="brandon@backscatter.io" \
      license="APLv2" \
      title="BackscatterIO" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . BackscatterIO_GetObservations

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r BackscatterIO_GetObservations/requirements.txt

ENTRYPOINT BackscatterIO/backscatter-io.py