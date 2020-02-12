FROM python:3-alpine

LABEL author="Andrea Garavaglia, LDO-CERT" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="CuckooSandbox" \
      url="https://github.com/garanews/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.2.0"

WORKDIR /worker

COPY . CuckooSandbox
RUN pip install --no-cache-dir -r CuckooSandbox/requirements.txt

ENTRYPOINT CuckooSandbox/cuckoosandbox_analyzer.py