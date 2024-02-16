FROM python:3-slim
WORKDIR /worker
COPY . Threatcrowd
RUN test ! -e Threatcrowd/requirements.txt || pip install --no-cache-dir -r Threatcrowd/requirements.txt
ENTRYPOINT Threatcrowd/threatcrowd_analyzer.py
