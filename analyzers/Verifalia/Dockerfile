FROM python:3.9-slim
WORKDIR /worker
COPY . Verifalia
RUN test ! -e Verifalia/requirements.txt || pip install --no-cache-dir -r Verifalia/requirements.txt
ENTRYPOINT Verifalia/Verifalia.py
