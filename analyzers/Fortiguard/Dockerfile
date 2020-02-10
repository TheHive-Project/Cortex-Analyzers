### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Fortiguard_URLCategory"
LABEL description="Check the Fortiguard category of a URL, FQDN or a domain. Check the full available list at https://fortiguard.com/webfilter/categories"
LABEL author="Eric Capuano"

WORKDIR /worker

COPY . Fortiguard_URLCategory

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Fortiguard_URLCategory/requirements.txt

ENTRYPOINT Fortiguard/urlcategory.py