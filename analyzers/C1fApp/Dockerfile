# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="C1fApp"
LABEL description="Query C1fApp OSINT Aggregator for IPs, domains and URLs"
LABEL author="etz69"

WORKDIR /worker

COPY . C1fApp

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r C1fApp/requirements.txt

ENTRYPOINT C1fApp/cifquery.py