### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="ANSSI, Sebastien Larinier @Sebdraven" \
      license="AGPL-V3" \
      title="Shodan" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers/Shodan" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Shodan_ReverseDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Shodan_ReverseDNS/requirements.txt

ENTRYPOINT Shodan/shodan_analyzer.py