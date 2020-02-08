# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="VMRay"
LABEL description="VMRay Sandbox file analysis."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . VMRay

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r VMRay/requirements.txt

ENTRYPOINT VMRay/vmray.py