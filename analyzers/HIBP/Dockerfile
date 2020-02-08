# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="HIBP_Query"
LABEL description="Query haveibeenpwned.com for a compromised email address"
LABEL author="Matt Erasmus, Jonas Hergenhahn"

WORKDIR /worker

COPY . HIBP_Query

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r HIBP_Query/requirements.txt

ENTRYPOINT HIBP/hibpquery_analyzer.py