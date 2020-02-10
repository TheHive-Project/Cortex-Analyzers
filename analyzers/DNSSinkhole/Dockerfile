### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="DNSSinkhole" \
      description="Check if a  domain is sinkholed via DNS Sinkhole server" \
      author="Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . DNSSinkhole

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r DNSSinkhole/requirements.txt

ENTRYPOINT DNSSinkhole/dnssinkhole.py