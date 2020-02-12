FROM python:3-alpine

LABEL author="Kyle Parrish" \
      description="Query the Umbrella Reporting API for recent DNS queries and their status." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Umbrella" \
      url="https://github.com/arnydo/thehive/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Umbrella
RUN pip install --no-cache-dir -r Umbrella/requirements.txt

ENTRYPOINT Umbrella/Umbrella.py