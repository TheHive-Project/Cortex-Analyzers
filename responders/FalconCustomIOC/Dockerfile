FROM python:2

WORKDIR /worker
COPY . FalconCustomIOC
RUN pip install --no-cache-dir -r FalconCustomIOC/requirements.txt
ENTRYPOINT FalconCustomIOC/FalconCustomIOC.py
