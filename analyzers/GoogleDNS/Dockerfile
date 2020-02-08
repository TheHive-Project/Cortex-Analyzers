# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="GoogleDNS_resolve"
LABEL description="Request Google DNS over HTTPS service"
LABEL author="CERT-LaPoste"

WORKDIR /worker

COPY . GoogleDNS_resolve

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleDNS_resolve/requirements.txt

ENTRYPOINT GoogleDNS/GoogleDNS_resolve.py