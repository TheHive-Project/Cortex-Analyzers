### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="TorProject"
LABEL description="Query https://check.torproject.org/exit-addresses for TOR exit nodes IP addresses."
LABEL author="Marc-André DOLL, STARC by EXAPROBE"

WORKDIR /worker

COPY . TorProject

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TorProject/requirements.txt

ENTRYPOINT TorProject/tor_project_analyzer.py