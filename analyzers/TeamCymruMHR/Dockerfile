### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="TeamCymruMHR" \
      description="Submit hash to Team Cymru's Malware Hash Registry" \
      author="Wes Lambert"

WORKDIR /worker

COPY . TeamCymruMHR

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TeamCymruMHR/requirements.txt

ENTRYPOINT TeamCymruMHR/TeamCymruMHR.py