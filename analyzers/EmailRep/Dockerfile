FROM python:3-alpine

LABEL author="Manabu Niseki" \
      description="emailrep.io lookup." \
      license="MIT" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="EmailRep" \
      url="https://github.com/ninoseki/emailrep-analyzer" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . EmailRep
RUN pip install --no-cache-dir -r EmailRep/requirements.txt

ENTRYPOINT EmailRep/emailrep_analyzer.py