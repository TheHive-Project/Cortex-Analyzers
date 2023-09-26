FROM python:3.10-slim
WORKDIR /worker
COPY . SentinelOne
RUN test ! -e SentinelOne/requirements.txt || pip install --no-cache-dir -r SentinelOne/requirements.txt
ENTRYPOINT "SentinelOne/SentinelOne.py"
