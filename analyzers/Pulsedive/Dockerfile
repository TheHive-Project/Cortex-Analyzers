FROM python:3-alpine

LABEL author="Nils Kuhnert" \
      description="Search Pulsedive.com for a giver domain name, hash, ip or url" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Pulsedive" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Pulsedive
RUN pip install --no-cache-dir -r Pulsedive/requirements.txt

ENTRYPOINT Pulsedive/pulsedive.py