### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Pulsedive_GetIndicator"
LABEL description="Search Pulsedive.com for a giver domain name, hash, ip or url"
LABEL author="Nils Kuhnert"

WORKDIR /worker

COPY . Pulsedive_GetIndicator

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Pulsedive_GetIndicator/requirements.txt

ENTRYPOINT Pulsedive/pulsedive.py