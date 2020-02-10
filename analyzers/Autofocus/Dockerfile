### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL name="AUTOFOCUS_GetSampleAnalysis"
LABEL description="Get full analysis from a sample based on its hash"
LABEL author="ANSSI"

WORKDIR /worker

COPY . AUTOFOCUS_GetSampleAnalysis

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r AUTOFOCUS_GetSampleAnalysis/requirements.txt

ENTRYPOINT Autofocus/analyzer.py