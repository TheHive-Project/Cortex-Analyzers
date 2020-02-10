### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Marc-André DOLL, STARC by EXAPROBE" \
      description="Query http://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv for TOR exit nodes IP addresses or names." \
      license="AGPL-V3" \
      title="TorBlutmagie" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . TorBlutmagie

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TorBlutmagie/requirements.txt

ENTRYPOINT TorBlutmagie/tor_blutmagie_analyzer.py