### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="GoogleSafebrowsing" \
      description="Use Google Safebrowing to check URLs and domain names." \
      author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . GoogleSafebrowsing

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GoogleSafebrowsing/requirements.txt

ENTRYPOINT GoogleSafebrowsing/safebrowsing_analyzer.py