FROM python:3-alpine

LABEL author="Rémi Allain, Cyberprotect" \
      description="Look up domains, mail and IP addresses on ThreatCrowd." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Threatcrowd" \
      url="https://github.com/Cyberprotect/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Threatcrowd
RUN pip install --no-cache-dir -r Threatcrowd/requirements.txt

ENTRYPOINT Threatcrowd/threatcrowd_analyzer.py