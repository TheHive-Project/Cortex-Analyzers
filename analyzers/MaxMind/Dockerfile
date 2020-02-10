### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Use MaxMind to geolocate an IP address." \
      license="AGPL-V3" \
      title="MaxMind" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="4.0.0"

WORKDIR /worker

COPY . MaxMind_GeoIP

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MaxMind_GeoIP/requirements.txt

ENTRYPOINT MaxMind/geo.py