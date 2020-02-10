### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="GreyNoise" \
      description="Determine whether an IP has known scanning activity using GreyNoise." \
      author="Nclose"

WORKDIR /worker

COPY . GreyNoise

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r GreyNoise/requirements.txt

ENTRYPOINT GreyNoise/greynoise.py