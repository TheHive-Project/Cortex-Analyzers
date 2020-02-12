FROM python:3-alpine

LABEL author="KAPSCH-CDC" \
      description="Get the latest risk data from RecordedFuture for a hash, domain or an IP address." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="RecordedFuture" \
      url="https://github.com/kapschcdc/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . RecordedFuture
RUN pip install --no-cache-dir -r RecordedFuture/requirements.txt

ENTRYPOINT RecordedFuture/recordedfuture.py