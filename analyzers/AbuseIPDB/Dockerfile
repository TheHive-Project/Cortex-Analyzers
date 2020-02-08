# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="AbuseIPDB"
LABEL description="Determine whether an IP was reported or not as malicious by AbuseIPDB"
LABEL author="Matteo Lodi"

WORKDIR /worker

COPY . AbuseIPDB

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r AbuseIPDB/requirements.txt

ENTRYPOINT AbuseIPDB/abuseipdb.py