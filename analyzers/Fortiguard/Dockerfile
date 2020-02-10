### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Eric Capuano" \
      description="Check the Fortiguard category of a URL, FQDN or a domain. Check the full available list at https://fortiguard.com/webfilter/categories" \
      license="AGPL-V3" \
      title="Fortiguard" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.1.0"

WORKDIR /worker

COPY . Fortiguard_URLCategory

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Fortiguard_URLCategory/requirements.txt

ENTRYPOINT Fortiguard/urlcategory.py