# See https://github.com/splunk/splunk-sdk-python for supported python versions
FROM python:3.7
WORKDIR /worker
COPY . Splunk
RUN test ! -e Splunk/requirements.txt || pip install --no-cache-dir -r Splunk/requirements.txt
ENTRYPOINT Splunk/splunk.py
