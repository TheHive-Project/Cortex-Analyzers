# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="Abuse_Finder"
LABEL description="Find abuse contacts associated with domain names, URLs, IPs and email addresses."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . Abuse_Finder

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Abuse_Finder/requirements.txt

ENTRYPOINT Abuse_Finder/abusefinder.py