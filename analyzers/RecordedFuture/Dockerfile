### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="RecordedFuture" \
      description="Get the latest risk data from RecordedFuture for a hash, domain or an IP address." \
      author="KAPSCH-CDC"

WORKDIR /worker

COPY . RecordedFuture_risk

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r RecordedFuture_risk/requirements.txt

ENTRYPOINT RecordedFuture/recordedfuture.py