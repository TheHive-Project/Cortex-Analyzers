# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="PhishingInitiative_Lookup"
LABEL description="Use Phishing Initiative to check if a URL is a verified phishing site."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . PhishingInitiative_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r PhishingInitiative_Lookup/requirements.txt

ENTRYPOINT PhishingInitiative/phishinginitiative_lookup.py