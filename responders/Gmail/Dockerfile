FROM python:3

WORKDIR /worker
COPY . Gmail
RUN pip install --no-cache-dir -r Gmail/requirements.txt
ENTRYPOINT Gmail/Gmail.py
