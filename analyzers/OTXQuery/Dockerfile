### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="OTXQuery"
LABEL description="Query AlienVault OTX for IPs, domains, URLs, or file hashes."
LABEL author="Eric Capuano"

WORKDIR /worker

COPY . OTXQuery

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r OTXQuery/requirements.txt

ENTRYPOINT OTXQuery/otxquery.py