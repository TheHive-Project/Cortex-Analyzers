### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache gcc musl-dev

LABEL name="Yara"
LABEL description="Check files against YARA rules."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . Yara

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Yara/requirements.txt

ENTRYPOINT Yara/yara_analyzer.py