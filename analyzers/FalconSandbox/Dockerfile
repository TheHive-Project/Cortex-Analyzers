FROM python:3
WORKDIR /worker
COPY . FalconSandbox
RUN test ! -e FalconSandbox/requirements.txt || pip install --no-cache-dir -r FalconSandbox/requirements.txt
ENTRYPOINT FalconSandbox/FalconSandbox.py
