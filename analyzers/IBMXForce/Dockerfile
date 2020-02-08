# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="IBMXForce_Lookup"
LABEL description="Query domains, IPs, hashes and URLs against IBM X-Force threat intelligence sharing platform."
LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . IBMXForce_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r IBMXForce_Lookup/requirements.txt

ENTRYPOINT IBMXForce/ibmxforce_lookup.py