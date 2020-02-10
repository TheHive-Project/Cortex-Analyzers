### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Virusshare"
LABEL description="Search for MD5 hashes in Virusshare.com hash list"
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . Virusshare

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Virusshare/requirements.txt

ENTRYPOINT Virusshare/virusshare.py