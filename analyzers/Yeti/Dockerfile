FROM python:3-alpine
WORKDIR /worker

RUN apk add --no-cache git

COPY requirements.txt Yeti/
RUN test ! -e Yeti/requirements.txt || pip install --no-cache-dir -r Yeti/requirements.txt
COPY . Yeti/

ENTRYPOINT ["python", "Yeti/yeti.py"]