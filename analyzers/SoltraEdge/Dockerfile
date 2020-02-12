FROM python:3-alpine

LABEL author="Michael Stensrud, Nordic Financial CERT" \
      description="Query against Soltra Edge." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="SoltraEdge" \
      url="http://soltra.com/en/" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . SoltraEdge
RUN pip install --no-cache-dir -r SoltraEdge/requirements.txt

ENTRYPOINT SoltraEdge/soltra.py