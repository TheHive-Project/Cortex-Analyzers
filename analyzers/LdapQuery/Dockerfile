# pull official base image
FROM python:3.9-slim

# Set ARGS
ARG ANALYZER_NAME

# set work directory
WORKDIR /app/

# Copy the current directory contents into the container at /worker
COPY . LdapQuery/

# install python3 pip3 and openssl
RUN apt update
RUN apt install python3 python3-pip openssl -y

# install dependencies using builder
RUN pip3 install -r LdapQuery/requirements.txt

# Run app.py when the container launches
ENTRYPOINT ["python","LdapQuery/ldapQuery.py"]