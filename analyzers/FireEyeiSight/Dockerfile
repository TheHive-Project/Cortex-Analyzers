# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="FireEyeiSight"
LABEL description="Query domains, IPs, hashes and URLs on FireEye's iSIGHT threat intelligence service."
LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . FireEyeiSight

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r FireEyeiSight/requirements.txt

ENTRYPOINT FireEyeiSight/fireeyeisight_lookup.py