### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Investigate" \
      description="Retrieve Investigate categorization and security features for a domain." \
      author="Cisco Umbrella Research @opendns"

WORKDIR /worker

COPY . Investigate_Categorization

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Investigate_Categorization/requirements.txt

ENTRYPOINT Investigate/investigate_analyzer.py