### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="staxx" \
      description="Fetch observable details from an Anomali STAXX instance." \
      author="Robert Nixon"

WORKDIR /worker

COPY . StaxxSearch

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r StaxxSearch/requirements.txt

ENTRYPOINT StaxxSearch/staxx-cortex.py