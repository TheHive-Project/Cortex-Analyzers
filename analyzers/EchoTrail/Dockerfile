FROM python:3.10-alpine
WORKDIR /worker
COPY requirements.txt EchoTrail/
RUN pip3 install --no-cache-dir -r EchoTrail/requirements.txt
COPY . EchoTrail/
ENTRYPOINT ["python3", "EchoTrail/echotrail.py"]
