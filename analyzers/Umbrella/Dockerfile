### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Umbrella_Report"
LABEL description="Query the Umbrella Reporting API for recent DNS queries and their status."
LABEL author="Kyle Parrish"

WORKDIR /worker

COPY . Umbrella_Report

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Umbrella_Report/requirements.txt

ENTRYPOINT Umbrella/Umbrella.py