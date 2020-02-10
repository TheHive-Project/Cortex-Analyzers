### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Michael Stensrud, Nordic Financial CERT" \
      license="AGPL-V3" \
      title="Mnemonic_pDNS" \
      url="https://passivedns.mnemonic.no/search" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . Mnemonic_pDNS_Public

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Mnemonic_pDNS_Public/requirements.txt

ENTRYPOINT MnemonicPDNS/pdns.py