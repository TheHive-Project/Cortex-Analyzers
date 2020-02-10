### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="CyberCrime-Tracker"
LABEL description="Search cybercrime-tracker.net for C2 servers."
LABEL author="ph34tur3"

WORKDIR /worker

COPY . CyberCrime-Tracker

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CyberCrime-Tracker/requirements.txt

ENTRYPOINT CyberCrime-Tracker/cct.py