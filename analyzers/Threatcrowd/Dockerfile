### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Threatcrowd" \
      description="Look up domains, mail and IP addresses on ThreatCrowd." \
      author="Rémi Allain, Cyberprotect"

WORKDIR /worker

COPY . Threatcrowd

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Threatcrowd/requirements.txt

ENTRYPOINT Threatcrowd/threatcrowd_analyzer.py