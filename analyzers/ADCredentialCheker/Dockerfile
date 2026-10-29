FROM python:3.11-slim
WORKDIR /worker

COPY requirements.txt ad-creds-checker.py /worker/
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "ad-creds-checker.py"]