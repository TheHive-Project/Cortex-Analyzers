### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL authors="Pierre Baudry, Adrien Barchapt, ANSSI" \
      description="Retrieve reverse DNS lookup information Onyphe has for the given IPv{4,6} address with history of changes." \
      license="AGPL-V3" \
      title="Onyphe" \
      url="https://github.com/cybernardo/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Onyphe_Reverse

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Onyphe_Reverse/requirements.txt

ENTRYPOINT Onyphe/onyphe_analyzer.py