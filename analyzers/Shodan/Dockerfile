# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Shodan_ReverseDNS"
LABEL description="Retrieve ip reverse DNS resolutions on Shodan."
LABEL author="ANSSI"

WORKDIR /worker

COPY . Shodan_ReverseDNS

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Shodan_ReverseDNS/requirements.txt

ENTRYPOINT Shodan/shodan_analyzer.py