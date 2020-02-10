### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Cisco Umbrella Research @opendns" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Investigate" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers/Investigate" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Investigate

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Investigate/requirements.txt

ENTRYPOINT Investigate/investigate_analyzer.py