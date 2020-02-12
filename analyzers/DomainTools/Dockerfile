FROM python:3-alpine

RUN apk add --no-cache gcc git musl-dev

LABEL authors="ANSSI, CERT-BDF" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="DomainTools" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . DomainTools
RUN pip install --no-cache-dir -r DomainTools/requirements.txt

ENTRYPOINT DomainTools/domaintools_analyzer.py