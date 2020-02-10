### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache git

LABEL name="AutoFocus" \
      description="Get full analysis from a sample based on its hash" \
      author="ANSSI"

WORKDIR /worker

COPY . AutoFocus_GetSampleAnalysis

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r AutoFocus_GetSampleAnalysis/requirements.txt

ENTRYPOINT AutoFocus/analyzer.py