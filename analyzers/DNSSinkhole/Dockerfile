FROM python:3-alpine

LABEL author="Andrea Garavaglia, LDO-CERT" \
      description="Check if a  domain is sinkholed via DNS Sinkhole server" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="DNSSinkhole" \
      url="https://github.com/LDO-CERT/cortex-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . DNSSinkhole
RUN pip install --no-cache-dir -r DNSSinkhole/requirements.txt

ENTRYPOINT DNSSinkhole/dnssinkhole.py