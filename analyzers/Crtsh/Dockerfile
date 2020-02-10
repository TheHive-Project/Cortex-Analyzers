### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="crackytsi" \
      description="Query domains against the certificate transparency lists available at crt.sh." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Crtsh" \
      url="https://crt.sh" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Crt_sh_Transparency_Logs

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Crt_sh_Transparency_Logs/requirements.txt

ENTRYPOINT Crtsh/crtshquery.py