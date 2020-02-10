### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Parse Outlook MSG files and extract the main artifacts." \
      license="AGPL-V3" \
      title="MsgParser" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . Msg_Parser

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Msg_Parser/requirements.txt

ENTRYPOINT MsgParser/parse.py