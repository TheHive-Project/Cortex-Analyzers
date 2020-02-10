### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT" \
      description="Retrieve ET details and info related to a malware hash." \
      license="AGPL-V3" \
      title="EmergingThreats" \
      url="https://github.com/dadokkio/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . EmergingThreats_MalwareInfo

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r EmergingThreats_MalwareInfo/requirements.txt

ENTRYPOINT EmergingThreats/emergingthreats_analyzer.py