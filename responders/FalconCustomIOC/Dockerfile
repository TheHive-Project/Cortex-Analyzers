FROM python:3

WORKDIR /worker
COPY . FalconCustomIOC
RUN pip install --no-cache-dir -r FalconCustomIOC/requirements.txt
ENTRYPOINT FalconCustomIOC/FalconCustomIOCv2.py