### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check CIRCL's Passive DNS for a given domain or URL." \
      license="AGPL-V3" \
      title="CIRCL" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . CIRCLPassiveDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CIRCLPassiveDNS/requirements.txt

ENTRYPOINT CIRCLPassiveDNS/circl_passivedns.py