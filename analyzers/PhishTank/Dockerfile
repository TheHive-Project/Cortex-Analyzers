### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="PhishTank" \
      description="Use PhishTank to check if a URL is a verified phishing site." \
      author="Eric Capuano"

WORKDIR /worker

COPY . PhishTank_CheckURL

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PhishTank_CheckURL/requirements.txt

ENTRYPOINT PhishTank/phishtank_checkurl.py