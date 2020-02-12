FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check IP addresses against the FireHOL blocklists" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="FireHOLBlocklists" \
      url="https://github.com/BSI-CERT-Bund/cortex-analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . FireHOLBlocklists
RUN pip install --no-cache-dir -r FireHOLBlocklists/requirements.txt

ENTRYPOINT FireHOLBlocklists/firehol_blocklists.py