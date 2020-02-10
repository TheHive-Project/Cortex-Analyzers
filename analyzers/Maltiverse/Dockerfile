### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL name="Maltiverse_Report"
LABEL description="Get the latest Maltiverse report for an hash, domain or an IP address."
LABEL author="ottimo"

WORKDIR /worker

COPY . Maltiverse_Report

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Maltiverse_Report/requirements.txt

ENTRYPOINT Maltiverse/maltiverse-client.py