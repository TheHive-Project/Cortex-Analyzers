FROM python:3.10-alpine
WORKDIR /worker
COPY requirements.txt PaloAltoWildFire/
RUN pip3 install --no-cache-dir -r PaloAltoWildFire/requirements.txt
COPY . PaloAltoWildFire
ENTRYPOINT ["python3", "PaloAltoWildFire/wildfire.py"]
