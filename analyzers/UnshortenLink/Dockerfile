FROM python:3-alpine

LABEL author="Remi Pointel, CERT-BDF" \
      description="Use UnshortenLink to reveal the real URL." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="UnshortenLink" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.2.0"

WORKDIR /worker

COPY . UnshortenLink
RUN pip install --no-cache-dir -r UnshortenLink/requirements.txt

ENTRYPOINT UnshortenLink/unshortenlink.py