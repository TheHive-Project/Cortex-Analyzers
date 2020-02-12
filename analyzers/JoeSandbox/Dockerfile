FROM python:3-alpine

LABEL author="CERT-BDF" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="JoeSandbox" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . JoeSandbox
RUN pip install --no-cache-dir -r JoeSandbox/requirements.txt

ENTRYPOINT JoeSandbox/joesandbox_analyzer.py