# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="TalosReputation"
LABEL description="Get the Talos IP reputation"
LABEL author="Gabriel Antonio da Silva"

WORKDIR /worker

COPY . TalosReputation

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r TalosReputation/requirements.txt

ENTRYPOINT TalosReputation/TalosReputation.py