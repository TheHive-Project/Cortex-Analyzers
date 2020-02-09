### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="ProofPoint_Lookup"
LABEL description="Check URL, file, SHA256 against ProofPoint forensics"
LABEL author="Emmanuel Torquato"

WORKDIR /worker

COPY . ProofPoint_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r ProofPoint_Lookup/requirements.txt

ENTRYPOINT ProofPoint/proofpoint_lookup.py