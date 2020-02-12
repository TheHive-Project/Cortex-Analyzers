FROM python:3-alpine

LABEL author="Matteo Lodi" \
      description="Determine whether an IP was reported or not as malicious by AbuseIPDB" \
      license="AGPL-v3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="AbuseIPDB" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . AbuseIPDB

RUN pip install --no-cache-dir -r AbuseIPDB/requirements.txt

ENTRYPOINT AbuseIPDB/abuseipdb.py