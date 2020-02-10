### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Rémi Allain, Cyberprotect" \
      description="ThreatScore is a cyber threat scoring system provided by Cyberprotect" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Cyberprotect" \
      url="https://github.com/Cyberprotect/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Cyberprotect_ThreatScore

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Cyberprotect_ThreatScore/requirements.txt

ENTRYPOINT Cyberprotect/CyberprotectAnalyzer.py