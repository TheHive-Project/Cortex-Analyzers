### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert" \
      description="Check IPs using the Robtex reverse passive DNS API." \
      license="AGPL-V3" \
      title="Robtex" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Robtex_Reverse_PDNS_Query

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Robtex_Reverse_PDNS_Query/requirements.txt

ENTRYPOINT Robtex/robtex.py