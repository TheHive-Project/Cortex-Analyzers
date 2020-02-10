### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="PassiveTotal_Ssl_Certificate_Details"
LABEL description="PassiveTotal SSL Certificate Details Lookup."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . PassiveTotal_Ssl_Certificate_Details

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PassiveTotal_Ssl_Certificate_Details/requirements.txt

ENTRYPOINT PassiveTotal/passivetotal_analyzer.py