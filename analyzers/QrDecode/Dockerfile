FROM python:3-slim
WORKDIR /worker
COPY . QrDecode
RUN test ! -e QrDecode/requirements.txt || pip install --no-cache-dir -r QrDecode/requirements.txt
RUN apt-get update && \
    apt-get install -y libzbar0 poppler-utils
ENTRYPOINT ["QrDecode/qrdecode.py"]
