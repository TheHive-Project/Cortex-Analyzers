FROM python:2

WORKDIR /worker
COPY . Abuse_Finder
RUN pip install --no-cache-dir -r Abuse_Finder/requirements.txt
ENTRYPOINT Abuse_Finder/abusefinder.py
