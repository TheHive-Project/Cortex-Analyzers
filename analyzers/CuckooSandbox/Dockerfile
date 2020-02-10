### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Andrea Garavaglia, LDO-CERT" \
      description="Cuckoo Sandbox file analysis with Internet access." \
      license="AGPL-V3" \
      title="CuckooSandbox" \
      url="https://github.com/garanews/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.2.0"

WORKDIR /worker

COPY . CuckooSandbox_File_Analysis_Inet

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CuckooSandbox_File_Analysis_Inet/requirements.txt

ENTRYPOINT CuckooSandbox/cuckoosandbox_analyzer.py