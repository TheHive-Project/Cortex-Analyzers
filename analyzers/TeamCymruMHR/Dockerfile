FROM python:3-alpine

LABEL author="Wes Lambert" \
      description="Submit hash to Team Cymru's Malware Hash Registry" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="TeamCymruMHR" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . TeamCymruMHR
RUN pip install --no-cache-dir -r TeamCymruMHR/requirements.txt

ENTRYPOINT TeamCymruMHR/TeamCymruMHR.py