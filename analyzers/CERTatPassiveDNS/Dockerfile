### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="CERTatPassiveDNS"
LABEL description="Checks CERT.at Passive DNS for a given domain."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . CERTatPassiveDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CERTatPassiveDNS/requirements.txt

ENTRYPOINT CERTatPassiveDNS/certat_passivedns.py