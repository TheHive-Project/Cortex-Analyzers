### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="DNSDB_IPHistory"
LABEL description="Use DNSDB to fetch historical records for an IP address."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . DNSDB_IPHistory

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DNSDB_IPHistory/requirements.txt

ENTRYPOINT DNSDB/dnsdb.py