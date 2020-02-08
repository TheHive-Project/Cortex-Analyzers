# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Censys"
LABEL description="Check IPs, certificate hashes or domains against censys.io."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . Censys

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Censys/requirements.txt

ENTRYPOINT Censys/censys_analyzer.py