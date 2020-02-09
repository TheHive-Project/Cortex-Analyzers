### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="Nessus"
LABEL description="Use Nessus Professional to scan hosts."
LABEL author="Guillaume Rousse"

WORKDIR /worker

COPY . Nessus

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Nessus/requirements.txt

ENTRYPOINT Nessus/nessus.py