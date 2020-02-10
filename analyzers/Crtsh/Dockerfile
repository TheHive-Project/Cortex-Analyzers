### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="Crtsh" \
      description="Query domains against the certificate transparency lists available at crt.sh." \
      author="crackytsi"

WORKDIR /worker

COPY . Crt_sh_Transparency_Logs

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Crt_sh_Transparency_Logs/requirements.txt

ENTRYPOINT Crtsh/crtshquery.py