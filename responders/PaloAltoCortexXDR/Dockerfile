FROM python:3.10-alpine
WORKDIR /worker
COPY requirements.txt PaloAltoCortexXDR/
RUN pip3 install --no-cache-dir -r PaloAltoCortexXDR/requirements.txt
COPY . PaloAltoCortexXDR/
ENTRYPOINT ["python3", "PaloAltoCortexXDR/cortex_xdr.py"]
