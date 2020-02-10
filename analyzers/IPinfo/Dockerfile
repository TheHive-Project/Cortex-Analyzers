### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="IPinfo_Details"
LABEL description="IPinfo details lookup."
LABEL author="Manabu Niseki"

WORKDIR /worker

COPY . IPinfo_Details

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r IPinfo_Details/requirements.txt

ENTRYPOINT IPinfo/ipinfo_analyzer.py