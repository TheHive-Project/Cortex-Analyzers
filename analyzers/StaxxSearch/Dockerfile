### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Robert Nixon" \
      description="Fetch observable details from an Anomali STAXX instance." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="staxx" \
      url="https://github.com/robertnixon2003/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . StaxxSearch

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r StaxxSearch/requirements.txt

ENTRYPOINT StaxxSearch/staxx-cortex.py