#!/usr/bin/env python3
# encoding: utf-8

import socket
import select
import re
from io import BytesIO
from cortexutils.analyzer import Analyzer


divider_pattern = re.compile(br'^(.*?)\r?\n(.*?)\r?\n\r?\n', re.DOTALL)
first_line_pattern = re.compile(br'^SPAMD/[^ ]+ 0 EX_OK$')


class SpamAssassinAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        url = self.get_param("config.url", None)
        port = self.get_param("config.port", None)
        self.spam_score = self.get_param("config.spam_score", 5)
        self.timeout = self.get_param("config.timeout", 20)
        if url and port:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.settimeout(self.timeout)  
            self.client.connect((url, port))


    def _build_message(self, message):
        reqfp = BytesIO()
        data_len = str(len(message)).encode()
        reqfp.write(b'REPORT SPAMC/1.2\r\n')
        reqfp.write(b'Content-Length: ' + data_len + b'\r\n')
        reqfp.write(b'User: cx42\r\n\r\n')
        reqfp.write(message)
        return reqfp.getvalue()


    def _parse_response(self, response):
        if response == b'':
            return None

        match = divider_pattern.match(response)
        if not match:
            return None

        first_line = match.group(1)
        headers = match.group(2)
        body = response[match.end(0):]

        match = first_line_pattern.match(first_line)
        if not match:
            return None

        report_list = [s.strip() for s in body.decode('utf-8', errors="ignore").strip().split('\n')]
        linebreak_num = report_list.index([s for s in report_list if "---" in s][0])
        tablelists = [s for s in report_list[linebreak_num + 1:]]

        tablelists_temp = []
        if tablelists:
            for counter, tablelist in enumerate(tablelists):
                if len(tablelist)>1:
                    if (tablelist[0].isnumeric() or tablelist[0] == '-') and (tablelist[1].isnumeric() or tablelist[1] == '.'):
                        tablelists_temp.append(tablelist)
                    else:
                        if tablelists_temp:
                            tablelists_temp[-1] += " " + tablelist
        tablelists = tablelists_temp

        report_json = {"values": []}
        for tablelist in tablelists:
            wordlist = re.split('\s+', tablelist)
            report_json['values'].append({'partscore': float(wordlist[0]), 'description': ' '.join(wordlist[1:]), 'name': wordlist[1]})

        headers = headers.decode('utf-8').replace(' ', '').replace(':', ';').replace('/', ';').split(';')
        report_json['score'] = float(headers[2])
        report_json['is_spam'] = float(headers[2]) > self.spam_score
        return report_json


    def summary(self, raw):
        taxonomies = []
        level = "suspicious" if raw.get('is_spam', None) else "info"
        taxonomies.append(self.build_taxonomy(level, "Spamassassin", "score", raw.get('score', 0)))
        return {"taxonomies": taxonomies}


    def run(self):
        Analyzer.run(self)

        data = self.get_param("file", None, "File is missing")
        if self.data_type != "file":
            self.error("Invalid data type")

        with open(data, 'rb') as f:
           message =  f.read()

        self.client.sendall(self._build_message(message))
        self.client.shutdown(socket.SHUT_WR)

        resfp = BytesIO()
        while True:
            ready = select.select([self.client], [], [], self.timeout)
            if ready[0] is None:
                self.error("Timeout during socket operation")

            data = self.client.recv(4096)
            if data == b'':
                break

            resfp.write(data)

        self.client.close()
        self.client = None

        
        self.report(self._parse_response(resfp.getvalue()))


if __name__ == "__main__":
    SpamAssassinAnalyzer().run()