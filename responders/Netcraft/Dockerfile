FROM python:3

WORKDIR /worker
COPY . Netcraft
RUN pip install --no-cache-dir -r Netcraft/requirements.txt
ENTRYPOINT Netcraft/Netcraft.py
