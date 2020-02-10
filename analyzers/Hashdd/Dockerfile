### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Hashdd_Status"
LABEL description="Determine whether a hash is good or bad."
LABEL author="iosonogio"

WORKDIR /worker

COPY . Hashdd_Status

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Hashdd_Status/requirements.txt

ENTRYPOINT Hashdd/Hashdd.py