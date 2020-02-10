### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Michael Stensrud, Nordic Financial CERT" \
      description="Query against Soltra Edge." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Soltra_Edge" \
      url="http://soltra.com/en/" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Soltra_Edge

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Soltra_Edge/requirements.txt

ENTRYPOINT SoltraEdge/soltra.py