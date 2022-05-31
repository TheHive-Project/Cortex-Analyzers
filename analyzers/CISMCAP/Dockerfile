FROM python:3.10-alpine
ARG name=CISMCAP
WORKDIR /worker
COPY requirements.txt ${name}/
RUN pip3 install --no-cache-dir -r ${name}/requirements.txt
COPY . ${name}
ENTRYPOINT ["python3", "${name}/mcap.py"]
