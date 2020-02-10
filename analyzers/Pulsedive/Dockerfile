### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert" \
      description="Search Pulsedive.com for a giver domain name, hash, ip or url" \
      license="AGPL-V3" \
      title="Pulsedive" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Pulsedive_GetIndicator

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Pulsedive_GetIndicator/requirements.txt

ENTRYPOINT Pulsedive/pulsedive.py