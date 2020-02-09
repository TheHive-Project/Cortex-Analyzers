### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="GreyNoise"
LABEL description="Determine whether an IP has known scanning activity using GreyNoise."
LABEL author="Nclose"

WORKDIR /worker

COPY . GreyNoise

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GreyNoise/requirements.txt

ENTRYPOINT GreyNoise/greynoise.py