FROM python:3.9

WORKDIR /worker
COPY . DShield

RUN pip install --no-cache-dir -r DShield/requirements.txt

ENTRYPOINT DShield/DShield_lookup.py