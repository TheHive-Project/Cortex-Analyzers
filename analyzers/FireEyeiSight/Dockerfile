### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT" \
      description="Query domains, IPs, hashes and URLs on FireEye's iSIGHT threat intelligence service." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="FireEyeiSight" \
      url="https://github.com/LDO-CERT/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . FireEyeiSight

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r FireEyeiSight/requirements.txt

ENTRYPOINT FireEyeiSight/fireeyeisight_lookup.py