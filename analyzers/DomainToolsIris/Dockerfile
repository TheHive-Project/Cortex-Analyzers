FROM python:3-alpine

RUN apk add --no-cache gcc git musl-dev

LABEL author="DomainTools" \
      description="Use DomainTools Iris API to pivot on ssl_hash, ip, or email." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="DomainToolsIris" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . DomainToolsIris
RUN pip install --no-cache-dir -r DomainToolsIris/requirements.txt

ENTRYPOINT DomainToolsIris/domaintoolsiris_analyzer.py