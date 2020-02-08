# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="CIRCLPassiveDNS"
LABEL description="Check CIRCL's Passive DNS for a given domain or URL."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . CIRCLPassiveDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CIRCLPassiveDNS/requirements.txt

ENTRYPOINT CIRCLPassiveDNS/circl_passivedns.py