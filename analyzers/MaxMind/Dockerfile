### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="MaxMind_GeoIP"
LABEL description="Use MaxMind to geolocate an IP address."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . MaxMind_GeoIP

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MaxMind_GeoIP/requirements.txt

ENTRYPOINT MaxMind/geo.py