### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="Hunterio_DomainSearch"
LABEL description="hunter.io is a service to find email addresses from a domain."
LABEL author="Rémi Allain, Cyberprotect"

WORKDIR /worker

COPY . Hunterio_DomainSearch

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Hunterio_DomainSearch/requirements.txt

ENTRYPOINT Hunterio/hunterio_analyzer.py