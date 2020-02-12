FROM python:3-alpine

LABEL author="Andrea Garavaglia, LDO-CERT" \
      description="Use Web of Trust to check a domain's reputation." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="WOT" \
      url="https://github.com/garanews/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . WOT
RUN pip install --no-cache-dir -r WOT/requirements.txt

ENTRYPOINT WOT/WOT_lookup.py