FROM python:3-slim
WORKDIR /worker
COPY . Maltiverse
RUN test ! -e Maltiverse/requirements.txt || pip install --no-cache-dir -r Maltiverse/requirements.txt
ENTRYPOINT Maltiverse/maltiverse-client.py
