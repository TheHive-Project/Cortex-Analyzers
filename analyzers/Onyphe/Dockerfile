### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Onyphe" \
      description="Retrieve reverse DNS lookup information Onyphe has for the given IPv{4,6} address with history of changes." \
      author="Pierre Baudry, Adrien Barchapt"

WORKDIR /worker

COPY . Onyphe_Reverse

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Onyphe_Reverse/requirements.txt

ENTRYPOINT Onyphe/onyphe_analyzer.py