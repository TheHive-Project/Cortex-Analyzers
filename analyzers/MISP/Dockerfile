### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="MISP" \
      description="Query multiple MISP instances for events containing an observable." \
      author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . MISP

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MISP/requirements.txt

ENTRYPOINT MISP/misp.py