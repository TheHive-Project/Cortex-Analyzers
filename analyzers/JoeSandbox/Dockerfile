### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="JoeSandbox" \
      description="Joe Sandbox file analysis with Internet access." \
      author="CERT-BDF"

WORKDIR /worker

COPY . JoeSandbox_File_Analysis_Inet

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r JoeSandbox_File_Analysis_Inet/requirements.txt

ENTRYPOINT JoeSandbox/joesandbox_analyzer.py