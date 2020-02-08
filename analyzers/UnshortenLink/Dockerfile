# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="UnshortenLink"
LABEL description="Use UnshortenLink to reveal the real URL."
LABEL author="Remi Pointel, CERT-BDF"

WORKDIR /worker

COPY . UnshortenLink

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r UnshortenLink/requirements.txt

ENTRYPOINT UnshortenLink/unshortenlink.py