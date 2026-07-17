FROM python:3-slim
WORKDIR /worker
RUN apt-get update && \
    apt-get install -y --no-install-recommends poppler-utils libmagic1 && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt PDFPreview/
RUN pip install --no-cache-dir -r PDFPreview/requirements.txt
COPY . PDFPreview/
ENTRYPOINT ["python", "PDFPreview/preview.py"]
