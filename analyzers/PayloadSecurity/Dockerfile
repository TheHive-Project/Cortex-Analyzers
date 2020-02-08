# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="PayloadSecurity_Url_Analysis"
LABEL description="PayloadSecurity Sandbox Url Analysis"
LABEL author="Emmanuel Torquato"

WORKDIR /worker

COPY . PayloadSecurity_Url_Analysis

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PayloadSecurity_Url_Analysis/requirements.txt

ENTRYPOINT PayloadSecurity/payloadsecurity_analyzer.py