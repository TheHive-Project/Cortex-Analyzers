### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL authors="ANSSI, CERT-BDF" \
      description="Use DomainTools to get a list of historical Whois records associated with a domain name." \
      license="AGPL-V3" \
      title="DomainTools" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . DomainTools_WhoisHistory

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DomainTools_WhoisHistory/requirements.txt

ENTRYPOINT DomainTools/domaintools_analyzer.py