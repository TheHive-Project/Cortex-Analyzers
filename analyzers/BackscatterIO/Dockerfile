FROM python:3-alpine

LABEL author="brandon@backscatter.io" \
      license="APLv2" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="BackscatterIO" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . BackscatterIO

RUN pip install --no-cache-dir -r BackscatterIO/requirements.txt

ENTRYPOINT BackscatterIO/backscatter-io.py