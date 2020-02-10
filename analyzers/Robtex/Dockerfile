### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Robtex" \
      description="Check IPs using the Robtex reverse passive DNS API." \
      author="Nils Kuhnert"

WORKDIR /worker

COPY . Robtex_Reverse_PDNS_Query

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Robtex_Reverse_PDNS_Query/requirements.txt

ENTRYPOINT Robtex/robtex.py