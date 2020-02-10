### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Rémi Allain, Cyberprotect" \
      description="hunter.io is a service to find email addresses from a domain." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Hunterio" \
      url="https://github.com/Cyberprotect/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Hunterio

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Hunterio/requirements.txt

ENTRYPOINT Hunterio/hunterio_analyzer.py