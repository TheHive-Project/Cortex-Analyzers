### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check if ip is sinkholed via sinkdb.abuse.ch" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="SinkDB" \
      url="https://github.com/BSI-CERT-Bund/sinkdb-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . SinkDB

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SinkDB/requirements.txt

ENTRYPOINT SinkDB/sinkdb.py