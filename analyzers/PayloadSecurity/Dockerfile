FROM python:3-alpine

LABEL author="Emmanuel Torquato" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="PayloadSecurity" \
      url="https://github.com/notset/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . PayloadSecurity
RUN pip install --no-cache-dir -r PayloadSecurity/requirements.txt

ENTRYPOINT PayloadSecurity/payloadsecurity_analyzer.py