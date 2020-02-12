### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Manabu Niseki" \
      description="emailrep.io lookup." \
      license="MIT" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="EmailRep" \
      url="https://github.com/ninoseki/emailrep-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . EmailRep

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r EmailRep/requirements.txt

ENTRYPOINT EmailRep/emailrep_analyzer.py