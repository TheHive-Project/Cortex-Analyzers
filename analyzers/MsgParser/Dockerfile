# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:2-alpine

LABEL name="Msg_Parser"
LABEL description="Parse Outlook MSG files and extract the main artifacts."
LABEL author="CERT-BDF"

WORKDIR /worker

COPY . Msg_Parser

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Msg_Parser/requirements.txt

ENTRYPOINT MsgParser/parse.py