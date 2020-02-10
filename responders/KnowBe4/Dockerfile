FROM python:3

WORKDIR /worker
COPY . KnowBe4
RUN pip install --no-cache-dir -r KnowBe4/requirements.txt
ENTRYPOINT KnowBe4/KnowBe4.py
