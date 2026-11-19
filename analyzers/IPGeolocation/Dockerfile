FROM python:3-slim
WORKDIR /worker
COPY requirements.txt IPGeolocation/
RUN pip install --no-cache-dir -r IPGeolocation/requirements.txt
COPY . IPGeolocation/
ENTRYPOINT ["python", "IPGeolocation/ipgeolocation_analyzer.py"]
