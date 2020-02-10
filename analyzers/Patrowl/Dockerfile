### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Patrowl_GetReport"
LABEL description="Get the current Patrowl report for a fdqn, a domain or an IP address."
LABEL author="Nicolas Mattiocco"

WORKDIR /worker

COPY . Patrowl_GetReport

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Patrowl_GetReport/requirements.txt

ENTRYPOINT Patrowl/patrowl.py