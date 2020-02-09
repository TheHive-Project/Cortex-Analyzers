### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="HippoMore"
LABEL description="Get the Hippocampe detailed report for an IP address, a domain or a URL."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . HippoMore

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r HippoMore/requirements.txt

ENTRYPOINT Hippocampe/hippo.py