# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="TorBlutmagie"
LABEL description="Query http://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv for TOR exit nodes IP addresses or names."
LABEL author="Marc-André DOLL, STARC by EXAPROBE"

WORKDIR /worker

COPY . TorBlutmagie

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TorBlutmagie/requirements.txt

ENTRYPOINT TorBlutmagie/tor_blutmagie_analyzer.py