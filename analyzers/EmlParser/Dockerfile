### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

RUN apk add --no-cache g++ gcc libmagic musl-dev

LABEL name="EmlParser"
LABEL description="Parse Eml message"
LABEL author="ninsmith"

WORKDIR /worker

COPY . EmlParser

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r EmlParser/requirements.txt

ENTRYPOINT EmlParser/parse.py