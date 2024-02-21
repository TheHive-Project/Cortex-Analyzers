FROM python:3.11

WORKDIR /worker
COPY . c25_analyzer

RUN pip install --no-cache-dir -r c25_analyzer/requirements.txt
ENTRYPOINT c25_analyzer/c25_cortex_analyzer.py