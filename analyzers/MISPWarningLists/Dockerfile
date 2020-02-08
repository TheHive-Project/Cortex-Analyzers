# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="MISPWarningLists"
LABEL description="Check IoCs/Observables against MISP Warninglists to filter false positives."
LABEL author="Nils Kuhnert, CERT-Bund"

WORKDIR /worker

COPY . MISPWarningLists

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MISPWarningLists/requirements.txt

ENTRYPOINT MISPWarningLists/mispwarninglists.py