# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Malpedia"
LABEL description="Check files against Malpedia YARA rules."
LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . Malpedia

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Malpedia/requirements.txt

ENTRYPOINT Malpedia/malpedia_analyzer.py