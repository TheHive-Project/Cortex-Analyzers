FROM python:3-alpine

WORKDIR /worker
RUN apk add --no-cache whois

COPY requirements.txt CERTatPassiveDNS/
RUN test ! -e CERTatPassiveDNS/requirements.txt || pip install --no-cache-dir -r CERTatPassiveDNS/requirements.txt
COPY . CERTatPassiveDNS/

ENTRYPOINT ["python", "CERTatPassiveDNS/certat_passivedns.py"]