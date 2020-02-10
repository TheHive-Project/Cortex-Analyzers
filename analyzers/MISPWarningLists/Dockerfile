### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="MISPWarningLists" \
      description="Check IoCs/Observables against MISP Warninglists to filter false positives." \
      author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . MISPWarningLists

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MISPWarningLists/requirements.txt

ENTRYPOINT MISPWarningLists/mispwarninglists.py