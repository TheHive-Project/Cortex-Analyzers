### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Marc-André DOLL, STARC by EXAPROBE" \
      description="Query https://check.torproject.org/exit-addresses for TOR exit nodes IP addresses." \
      license="AGPL-V3" \
      title="TorProject" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . TorProject

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TorProject/requirements.txt

ENTRYPOINT TorProject/tor_project_analyzer.py