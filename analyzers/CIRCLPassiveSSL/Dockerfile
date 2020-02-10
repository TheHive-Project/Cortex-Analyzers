### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="CIRCL" \
      description="Check CIRCL's Passive SSL for a given IP address or a X509 certificate hash." \
      author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . CIRCLPassiveSSL

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CIRCLPassiveSSL/requirements.txt

ENTRYPOINT CIRCLPassiveSSL/circl_passivessl.py