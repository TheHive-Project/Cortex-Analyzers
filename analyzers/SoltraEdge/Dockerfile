# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="SoltraEdge"
LABEL description="Query against Soltra Edge."
LABEL author="Michael Stensrud, Nordic Financial CERT"

WORKDIR /worker

COPY . SoltraEdge

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r SoltraEdge/requirements.txt

ENTRYPOINT SoltraEdge/soltra.py