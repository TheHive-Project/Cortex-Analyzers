FROM python:3-alpine

LABEL author="Nils Kuhnert, CERT-Bund" \
      description="Check IoCs/Observables against MISP Warninglists to filter false positives." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="MISPWarningLists" \
      url="https://github.com/BSI-CERT-Bund/misp-warninglists-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . MISPWarningLists
RUN pip install --no-cache-dir -r MISPWarningLists/requirements.txt

ENTRYPOINT MISPWarningLists/mispwarninglists.py