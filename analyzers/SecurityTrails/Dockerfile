### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Manabu Niseki, @ninoseki" \
      license="MIT" \
      title="SecurityTrails" \
      url="https://github.com/ninoseki/cortex-securitytrails" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . SecurityTrails_Whois

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SecurityTrails_Whois/requirements.txt

ENTRYPOINT SecurityTrails/securitytrails_analyzer.py