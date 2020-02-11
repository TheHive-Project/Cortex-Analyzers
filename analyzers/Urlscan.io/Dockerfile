### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="ninoseki" \
      description="Search IPs, domains, hashes or URLs on urlscan.io" \
      license="MIT" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Urlscan.io" \
      url="https://github.com/ninoseki/cortex_urlscan_analyzer" \
      vendor="TheHive" \
      version="0.1.0"

WORKDIR /worker

COPY . Urlscan.io

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Urlscan.io/requirements.txt

ENTRYPOINT Urlscan.io/urlscan_analyzer.py