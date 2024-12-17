FROM python:3
WORKDIR /worker
COPY . Capa

# Install required tools
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    unzip && \
    rm -rf /var/lib/apt/lists/*

# Add a script to fetch the latest capa release and extract it
COPY fetch_capa.sh /worker/fetch_capa.sh
RUN chmod +x /worker/fetch_capa.sh && /worker/fetch_capa.sh

RUN test ! -e Capa/requirements.txt || pip install --no-cache-dir -r Capa/requirements.txt
ENTRYPOINT "Capa/CapaAnalyze.py"