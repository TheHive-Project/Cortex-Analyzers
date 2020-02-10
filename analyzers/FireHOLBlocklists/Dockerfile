### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="FireHOLBlocklists" \
      description="Check IP addresses against the FireHOL blocklists" \
      author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . FireHOLBlocklists

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r FireHOLBlocklists/requirements.txt

ENTRYPOINT FireHOLBlocklists/firehol_blocklists.py