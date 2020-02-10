### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Use MaxMind to geolocate an IP address." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="MaxMind" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="4.0.0"

WORKDIR /worker

COPY . MaxMind

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MaxMind/requirements.txt

ENTRYPOINT MaxMind/geo.py