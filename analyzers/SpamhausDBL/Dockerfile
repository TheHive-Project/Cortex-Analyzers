### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Wes Lambert" \
      description="Perform domain lookup to Spamhaus DBL" \
      license="AGPL-V3" \
      title="SpamhausDBL" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . SpamhausDBL

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SpamhausDBL/requirements.txt

ENTRYPOINT SpamhausDBL/spamhausdbl.py