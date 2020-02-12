### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="ANSSI, Pierre Baudry, Adrien Barchapt" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Onyphe" \
      url="https://github.com/cybernardo/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Onyphe

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Onyphe/requirements.txt

ENTRYPOINT Onyphe/onyphe_analyzer.py