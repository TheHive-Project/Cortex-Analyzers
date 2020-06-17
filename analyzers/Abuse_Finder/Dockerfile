FROM python:3.6

WORKDIR /worker
COPY . Abuse_Finder
RUN pip3 install --no-cache-dir -r Abuse_Finder/requirements.txt
ENTRYPOINT Abuse_Finder/abusefinder.py
