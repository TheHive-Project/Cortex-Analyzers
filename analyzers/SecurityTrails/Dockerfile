### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="SecurityTrails_Whois"
LABEL description="SecurityTrails Whois Lookup."
LABEL author="Manabu Niseki, @ninoseki"

WORKDIR /worker

COPY . SecurityTrails_Whois

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SecurityTrails_Whois/requirements.txt

ENTRYPOINT SecurityTrails/securitytrails_analyzer.py