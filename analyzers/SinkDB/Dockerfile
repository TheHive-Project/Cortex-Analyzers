### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="SinkDB"
LABEL description="Check if ip is sinkholed via sinkdb.abuse.ch"
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . SinkDB

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SinkDB/requirements.txt

ENTRYPOINT SinkDB/sinkdb.py