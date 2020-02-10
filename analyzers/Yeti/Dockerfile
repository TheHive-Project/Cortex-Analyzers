### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Yeti" \
      description="Fetch observable details from a YETI instance." \
      author="CERT-BDF"

WORKDIR /worker

COPY . Yeti

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Yeti/requirements.txt

ENTRYPOINT Yeti/yeti.py