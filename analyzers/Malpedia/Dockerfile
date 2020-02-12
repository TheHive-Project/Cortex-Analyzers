FROM python:3-alpine

RUN apk add --no-cache gcc musl-dev

LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT" \
      description="Check files against Malpedia YARA rules." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Malpedia" \
      url="https://github.com/LDO-CERT/cortex-analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Malpedia
RUN pip install --no-cache-dir -r Malpedia/requirements.txt

ENTRYPOINT Malpedia/malpedia_analyzer.py