# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="WOT_Lookup"
LABEL description="Use Web of Trust to check a domain's reputation."
LABEL author="Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . WOT_Lookup

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r WOT_Lookup/requirements.txt

ENTRYPOINT WOT/WOT_lookup.py