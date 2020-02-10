### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Nicolas Mattiocco" \
      description="Get the current Patrowl report for a fdqn, a domain or an IP address." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Patrowl" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Patrowl

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Patrowl/requirements.txt

ENTRYPOINT Patrowl/patrowl.py