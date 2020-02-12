FROM python:3-alpine

LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT" \
      description="Query domains, IPs, hashes and URLs against IBM X-Force threat intelligence sharing platform." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="IBMXForce" \
      url="https://github.com/LDO-CERT/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . IBMXForce
RUN pip install --no-cache-dir -r IBMXForce/requirements.txt

ENTRYPOINT IBMXForce/ibmxforce_lookup.py