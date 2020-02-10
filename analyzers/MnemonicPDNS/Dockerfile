### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Mnemonic_pDNS_Public"
LABEL description="Query IP addresses and domains against Mnemonic pDNS public service."
LABEL author="Michael Stensrud, Nordic Financial CERT"

WORKDIR /worker

COPY . Mnemonic_pDNS_Public

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Mnemonic_pDNS_Public/requirements.txt

ENTRYPOINT MnemonicPDNS/pdns.py