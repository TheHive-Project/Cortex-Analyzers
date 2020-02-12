FROM python:3-alpine

LABEL author="CERT-BDF" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Hippocampe" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . Hippocampe
RUN pip install --no-cache-dir -r Hippocampe/requirements.txt

ENTRYPOINT Hippocampe/hippo.py