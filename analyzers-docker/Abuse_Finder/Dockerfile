FROM cortex-base-python2
ADD ./analyzers/Abuse_Finder /analyzer
WORKDIR /analyzer
RUN pip install --no-cache-dir -r requirements.txt
CMD ./abusefinder.py
