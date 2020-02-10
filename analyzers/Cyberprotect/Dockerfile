### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Cyberprotect" \
      description="ThreatScore is a cyber threat scoring system provided by Cyberprotect" \
      author="Rémi Allain, Cyberprotect"

WORKDIR /worker

COPY . Cyberprotect_ThreatScore

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Cyberprotect_ThreatScore/requirements.txt

ENTRYPOINT Cyberprotect/CyberprotectAnalyzer.py