FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check IPs, certificate hashes or domains against censys.io." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Censys" \
      url="https://github.com/BSI-CERT-Bund/censys-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Censys

RUN pip install --no-cache-dir -r Censys/requirements.txt

ENTRYPOINT Censys/censys_analyzer.py