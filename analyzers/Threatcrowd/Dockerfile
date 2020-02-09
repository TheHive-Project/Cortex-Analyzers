### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="Threatcrowd"
LABEL description="Look up domains, mail and IP addresses on ThreatCrowd."
LABEL author="Rémi Allain, Cyberprotect"

WORKDIR /worker

COPY . Threatcrowd

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Threatcrowd/requirements.txt

ENTRYPOINT Threatcrowd/threatcrowd_analyzer.py