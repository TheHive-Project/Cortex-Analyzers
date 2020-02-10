### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-LaPoste" \
      description="Find look alike image via Google Cloud Vision API using the Web_Detection service " \
      license="AGPL-V3" \
      title="GoogleVisionAPI" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . GoogleVisionAPI_WebDetection

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleVisionAPI_WebDetection/requirements.txt

ENTRYPOINT GoogleVisionAPI/GoogleVisionAPI_WebDetection.py