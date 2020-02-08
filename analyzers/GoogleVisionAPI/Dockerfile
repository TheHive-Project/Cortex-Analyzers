# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="GoogleVisionAPI_WebDetection"
LABEL description="Find look alike image via Google Cloud Vision API using the Web_Detection service "
LABEL author="CERT-LaPoste"

WORKDIR /worker

COPY . GoogleVisionAPI_WebDetection

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleVisionAPI_WebDetection/requirements.txt

ENTRYPOINT GoogleVisionAPI/GoogleVisionAPI_WebDetection.py