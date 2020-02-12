FROM python:3-alpine

LABEL author="ninoseki, Nils Kuhnert" \
      description="Search domains, IPs, URLs or hashes on URLhaus." \
      license="MIT" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="URLhaus" \
      url="https://github.com/ninoseki/cortex_URLhaus_analyzer" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . URLhaus
RUN pip install --no-cache-dir -r URLhaus/requirements.txt

ENTRYPOINT URLhaus/URLhaus_analyzer.py