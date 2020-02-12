FROM python:3-alpine

LABEL author="Daniil Yugoslavskiy, Tieto" \
      description="Fetch Hybrid Analysis reports associated with hashes and filenames." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="HybridAnalysis" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . HybridAnalysis
RUN pip install --no-cache-dir -r HybridAnalysis/requirements.txt

ENTRYPOINT HybridAnalysis/HybridAnalysis_analyzer.py