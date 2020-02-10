### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="EmergingThreats" \
      description="Retrieve ET details and info related to a malware hash." \
      author="Davide Arcuri and Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . EmergingThreats_MalwareInfo

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r EmergingThreats_MalwareInfo/requirements.txt

ENTRYPOINT EmergingThreats/emergingthreats_analyzer.py