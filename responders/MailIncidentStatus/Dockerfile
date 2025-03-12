FROM python:3-alpine

WORKDIR /worker

# install runtime dependencies
RUN apk add --no-cache file-dev

COPY requirements.txt MailIncidentStatus/

# Install Python dependencies from requirements.txt
RUN test ! -e MailIncidentStatus/requirements.txt || pip install --no-cache-dir -r MailIncidentStatus/requirements.txt

COPY . MailIncidentStatus

ENTRYPOINT ["python", "MailIncidentStatus/mailincidentstatus.py"]