FROM python:3-alpine

LABEL author="Robert Nixon" \
      description="Fetch observable details from an Anomali STAXX instance." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="StaxxSearch" \
      url="https://github.com/robertnixon2003/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . StaxxSearch
RUN pip install --no-cache-dir -r StaxxSearch/requirements.txt

ENTRYPOINT StaxxSearch/staxx-cortex.py