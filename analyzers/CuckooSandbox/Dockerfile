### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="CuckooSandbox_File_Analysis_Inet"
LABEL description="Cuckoo Sandbox file analysis with Internet access."
LABEL author="Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . CuckooSandbox_File_Analysis_Inet

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r CuckooSandbox_File_Analysis_Inet/requirements.txt

ENTRYPOINT CuckooSandbox/cuckoosandbox_analyzer.py