### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL name="DomainTools_WhoisHistory"
LABEL description="Use DomainTools to get a list of historical Whois records associated with a domain name."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . DomainTools_WhoisHistory

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DomainTools_WhoisHistory/requirements.txt

ENTRYPOINT DomainTools/domaintools_analyzer.py