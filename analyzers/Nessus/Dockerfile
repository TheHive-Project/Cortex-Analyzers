### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Guillaume Rousse" \
      description="Use Nessus Professional to scan hosts." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Nessus" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . Nessus

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Nessus/requirements.txt

ENTRYPOINT Nessus/nessus.py