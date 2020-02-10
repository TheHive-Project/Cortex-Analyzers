### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL name="DomainToolsIris_Pivot"
LABEL description="Use DomainTools Iris API to pivot on ssl_hash, ip, or email."
LABEL author="DomainTools"

WORKDIR /worker

COPY . DomainToolsIris_Pivot

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DomainToolsIris_Pivot/requirements.txt

ENTRYPOINT DomainToolsIris/domaintoolsiris_analyzer.py