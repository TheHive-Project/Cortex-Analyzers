### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Checks CERT.at Passive DNS for a given domain." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="CERTatPassiveDNS" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . CERTatPassiveDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CERTatPassiveDNS/requirements.txt

ENTRYPOINT CERTatPassiveDNS/certat_passivedns.py