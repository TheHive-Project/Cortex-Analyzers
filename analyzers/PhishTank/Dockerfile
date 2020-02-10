### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Eric Capuano" \
      description="Use PhishTank to check if a URL is a verified phishing site." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="PhishTank" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.1.0"

WORKDIR /worker

COPY . PhishTank_CheckURL

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PhishTank_CheckURL/requirements.txt

ENTRYPOINT PhishTank/phishtank_checkurl.py