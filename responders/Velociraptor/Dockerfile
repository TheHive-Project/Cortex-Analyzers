# keep python:3-slim because the wheel is too slow on alpine
FROM python:3-slim

WORKDIR /worker

# install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      libmagic-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt Velociraptor/

# Install Python dependencies from requirements.txt
RUN test ! -e Velociraptor/requirements.txt || pip install --no-cache-dir -r Velociraptor/requirements.txt

COPY . Velociraptor

ENTRYPOINT ["python", "Velociraptor/velociraptor_flow.py"]
