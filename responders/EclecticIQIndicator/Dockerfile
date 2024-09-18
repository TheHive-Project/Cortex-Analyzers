FROM python:2

WORKDIR /worker
COPY . EclecticIQIndicator
RUN pip install --no-cache-dir -r EclecticIQIndicator/requirements.txt
ENTRYPOINT EclecticIQIndicator/EclecticIQIndicator.py
