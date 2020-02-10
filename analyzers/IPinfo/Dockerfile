### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Manabu Niseki" \
      license="MIT" \
      title="IPinfo" \
      url="https://github.com/ninoseki/ipinfo-analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . IPinfo_Details

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r IPinfo_Details/requirements.txt

ENTRYPOINT IPinfo/ipinfo_analyzer.py