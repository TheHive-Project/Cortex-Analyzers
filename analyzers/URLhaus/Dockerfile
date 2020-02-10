### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="ninoseki, Nils Kuhnert" \
      description="Search domains, IPs, URLs or hashes on URLhaus." \
      license="MIT" \
      title="URLhaus" \
      url="https://github.com/ninoseki/cortex_URLhaus_analyzer" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . URLhaus

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r URLhaus/requirements.txt

ENTRYPOINT URLhaus/URLhaus_analyzer.py