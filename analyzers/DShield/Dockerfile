### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="DShield_lookup"
LABEL description="Query the SANS ISC DShield API to check for an IP address reputation."
LABEL author="Xavier Xavier, SANS ISC"

WORKDIR /worker

COPY . DShield_lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DShield_lookup/requirements.txt

ENTRYPOINT DShield/DShield_lookup.py