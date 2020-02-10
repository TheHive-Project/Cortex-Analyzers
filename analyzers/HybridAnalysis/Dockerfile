### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

# Guessing base image from source code shebang
FROM python:3-alpine

LABEL author="Daniil Yugoslavskiy, Tieto" \
      description="Fetch Hybrid Analysis reports associated with hashes and filenames." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="HybridAnalysis" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . HybridAnalysis_GetReport

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r HybridAnalysis_GetReport/requirements.txt

ENTRYPOINT HybridAnalysis/HybridAnalysis_analyzer.py