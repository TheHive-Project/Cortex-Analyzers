FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check CIRCL's Passive DNS for a given domain or URL." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="CIRCLPassiveDNS" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . CIRCLPassiveDNS

RUN pip install --no-cache-dir -r CIRCLPassiveDNS/requirements.txt

ENTRYPOINT CIRCLPassiveDNS/circl_passivedns.py