FROM python:3-slim
WORKDIR /worker
COPY . GoogleDNS
RUN test ! -e GoogleDNS/requirements.txt || pip install --no-cache-dir -r GoogleDNS/requirements.txt
ENTRYPOINT GoogleDNS/GoogleDNS_resolve.py
