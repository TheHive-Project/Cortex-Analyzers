FROM python:3

WORKDIR /worker
COPY . AWSInvokeLambda
RUN test ! -e AWSInvokeLambda/requirements.txt || pip install --no-cache-dir -r AWSInvokeLambda/requirements.txt
ENTRYPOINT AWSInvokeLambda/AWSInvokeLambda.py
