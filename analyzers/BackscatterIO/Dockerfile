### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="BackscatterIO_GetObservations"
LABEL description="Determine whether a value has known scanning activity using Backscatter.io data."
LABEL author="brandon@backscatter.io"

WORKDIR /worker

COPY . BackscatterIO_GetObservations

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r BackscatterIO_GetObservations/requirements.txt

ENTRYPOINT BackscatterIO/backscatter-io.py