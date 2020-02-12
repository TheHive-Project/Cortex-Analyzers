FROM python:3-alpine

LABEL author="Rémi Allain, Cyberprotect" \
      description="ThreatScore is a cyber threat scoring system provided by Cyberprotect" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Cyberprotect" \
      url="https://github.com/Cyberprotect/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Cyberprotect
RUN pip install --no-cache-dir -r Cyberprotect/requirements.txt

ENTRYPOINT Cyberprotect/CyberprotectAnalyzer.py