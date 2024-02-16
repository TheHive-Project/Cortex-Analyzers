FROM python:3.10-alpine
WORKDIR /worker
COPY requirements.txt CISMCAP/
RUN pip3 install --no-cache-dir -r CISMCAP/requirements.txt
COPY . CISMCAP/
ENTRYPOINT ["python3", "CISMCAP/mcap.py"]
