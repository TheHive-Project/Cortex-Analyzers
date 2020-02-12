FROM python:3-alpine

LABEL author="Xavier Xavier, SANS ISC" \
      description="Query the SANS ISC DShield API to check for an IP address reputation." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="DShield" \
      url="https://github.com/xme/thehive/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . DShield
RUN pip install --no-cache-dir -r DShield/requirements.txt

ENTRYPOINT DShield/DShield_lookup.py