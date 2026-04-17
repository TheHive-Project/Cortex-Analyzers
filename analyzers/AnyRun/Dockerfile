FROM python:3-alpine

WORKDIR /worker
RUN apk add --no-cache whois

COPY requirements.txt AnyRun/
RUN test ! -e AnyRun/requirements.txt || pip install --no-cache-dir -r AnyRun/requirements.txt
COPY . AnyRun/

ENTRYPOINT ["python", "AnyRun/anyrun_analyzer.py"]