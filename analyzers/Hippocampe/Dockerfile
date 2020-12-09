FROM python:2

WORKDIR /worker
COPY . Hippocampe
RUN pip install --no-cache-dir -r Hippocampe/requirements.txt
ENTRYPOINT Hippocampe/hippo.py
