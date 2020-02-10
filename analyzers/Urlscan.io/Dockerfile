### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Urlscan" \
      description="Search IPs, domains, hashes or URLs on urlscan.io" \
      author="ninoseki"

WORKDIR /worker

COPY . Urlscan.io_Search

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Urlscan.io_Search/requirements.txt

ENTRYPOINT Urlscan.io/urlscan_analyzer.py