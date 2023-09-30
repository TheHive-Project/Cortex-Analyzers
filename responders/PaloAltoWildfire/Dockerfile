FROM python:3

WORKDIR /worker
COPY . PaloAltoWildfire
RUN pip install --no-cache-dir -r PaloAltoWildfire/requirements.txt
ENTRYPOINT PaloAltoWildfire/PaloAltoWildfire.py
