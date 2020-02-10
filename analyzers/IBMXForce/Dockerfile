### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT" \
      description="Query domains, IPs, hashes and URLs against IBM X-Force threat intelligence sharing platform." \
      license="AGPL-V3" \
      title="IBMXForce" \
      url="https://github.com/LDO-CERT/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . IBMXForce_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r IBMXForce_Lookup/requirements.txt

ENTRYPOINT IBMXForce/ibmxforce_lookup.py