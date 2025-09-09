FROM python:3-slim
WORKDIR /worker

# Install required tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      jq \
      unzip \
      bash \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt Capa/
RUN test ! -e Capa/requirements.txt || pip install --no-cache-dir -r Capa/requirements.txt

# Add a script to fetch the latest capa release and extract it
COPY fetch_capa.sh /worker/fetch_capa.sh
RUN chmod +x /worker/fetch_capa.sh && /worker/fetch_capa.sh

COPY . Capa/

ENTRYPOINT ["python", "Capa/CapaAnalyze.py"]
