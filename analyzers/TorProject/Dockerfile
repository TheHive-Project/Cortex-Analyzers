FROM python:3-alpine

LABEL author="Marc-André DOLL, STARC by EXAPROBE" \
      description="Query https://check.torproject.org/exit-addresses for TOR exit nodes IP addresses." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="TorProject" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . TorProject
RUN pip install --no-cache-dir -r TorProject/requirements.txt

ENTRYPOINT TorProject/tor_project_analyzer.py