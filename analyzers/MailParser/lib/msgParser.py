#!/usr/bin/env python
# encoding: utf-8

# --- LICENSE -----------------------------------------------------------------
#
#    Copyright 2013 Matthew Walker
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import os
import sys
import glob
import traceback
from email.parser import Parser as EmailParser
import email.utils
import olefile as OleFile
import re
import hashlib
from pymisp import PyMISP
from multiprocessing import Pool
import subprocess
import requests
import time
import copy_reg
import types


# fix to write dict to file
def _pickle_method(m):
    if m.im_self is None:
        return getattr, (m.im_class, m.im_func.func_name)
    else:
        return getattr, (m.im_self, m.im_func.func_name)
copy_reg.pickle(types.MethodType, _pickle_method)

class Attachment:

    def __init__(self, msg, dir_):

        # print dir_

        # Get long filename
        self.longFilename = msg._getStringStream([dir_, '__substg1.0_3707'])
        # print  self.longFilename

        # Get short filename
        self.shortFilename = msg._getStringStream([dir_, '__substg1.0_3704'])

        # Get attachment data
        self.data = msg._getStream([dir_, '__substg1.0_37010102'])

        # Get short mimeTag
        self.mimeTag = msg._getStringStream([dir_, '__substg1.0_370E'])

        # Get extension
        self.extension = msg._getStringStream([dir_, '__substg1.0_3703'])

    def save(self):
        # Use long filename as first preference
        filename = self.longFilename

        # Otherwise use the short filename
        if filename is None:
            filename = self.shortFilename
        # Otherwise just make something up!
        if filename is None:
            import random
            import string
            filename = 'UnknownFilename ' + \
                       ''.join(random.choice(string.ascii_uppercase + string.digits)
                               for _ in range(5)) + ".bin"
        f = open("/tmp/" + filename, 'wb')
        if self.data is None:
            f.write(" ")
            f.close()
        else:
            f.write(self.data)
            f.close()
        return "/tmp/" + filename


def windowsUnicode(string):
    if string is None:
        return None
    if sys.version_info[0] >= 3:  # Python 3
        return str(string, 'utf_16_le')
    else:  # Python 2
        return unicode(string, 'utf_16_le')


class Message(OleFile.OleFileIO):

    def __init__(self, filename):
        OleFile.OleFileIO.__init__(self, filename)
        self.filename = filename

    def _getStream(self, filename):
        if self.exists(filename):
            stream = self.openstream(filename)
            return stream.read()
        else:
            return None

    def _getStringStream(self, filename, prefer='utf-8'):
        """Gets a string representation of the requested filename.
        Checks for both ASCII and Unicode representations and returns
        a value if possible.  If there are both ASCII and Unicode
        versions, then the parameter /prefer/ specifies which will be
        returned.
        """

        if isinstance(filename, list):
            # Join with slashes to make it easier to append the type
            filename = "/".join(filename)

        try:
            asciiVersion = self._getStream(filename + '001E')
        except:
            asciiVersion = None
        try:
            unicodeVersion = windowsUnicode(self._getStream(filename + '001F'))
        except:
            unicodeVersion = None

        if asciiVersion is None:
            return unicodeVersion
        elif unicodeVersion is None:
            return asciiVersion.decode('ascii', 'ignore')
        else:
            if prefer == 'unicode':
                return unicodeVersion
            else:
                return asciiVersion.decode('ascii', 'ignore')

    @property
    def subject(self):
        return self._getStringStream('__substg1.0_0037')

    @property
    def header(self):
        try:
            return self._header
        except Exception:
            headerText = self._getStringStream('__substg1.0_007D')
            if headerText is not None:
                self._header = EmailParser().parsestr(headerText)
            else:
                self._header = None
            return self._header

    @property
    def date(self):
        # Get the message's header and extract the date
        if self.header is None:
            return None
        else:
            return self.header['date']

    @property
    def parsedDate(self):
        return email.utils.parsedate(self.date)

    @property
    def attachments(self):
        try:
            return self._attachments
        except Exception:
            # Get the attachments
            attachmentDirs = []

            for dir_ in self.listdir():
                if dir_[0].startswith('__attach') and dir_[0] not in attachmentDirs:
                    attachmentDirs.append(dir_[0])

            self._attachments = []

            for attachmentDir in attachmentDirs:
                self._attachments.append(Attachment(self, attachmentDir))

            return self._attachments

    @property
    def sender(self):
        try:
            return self._sender
        except Exception:
            # Check header first
            if self.header is not None:
                headerResult = self.header["from"]
                if headerResult is not None:
                    self._sender = headerResult
                    return headerResult

            # Extract from other fields
            text = self._getStringStream('__substg1.0_0C1A')
            email = self._getStringStream('__substg1.0_0C1F')
            result = None
            if text is None:
                result = email
            else:
                result = text
                if email is not None:
                    result = result + " <" + email + ">"

            self._sender = result
            return result

    @property
    def to(self):
        try:
            return self._to
        except Exception:
            # Check header first
            if self.header is not None:
                headerResult = self.header["to"]
                if headerResult is not None:
                    self._to = headerResult
                    return headerResult

            # Extract from other fields
            # TODO: This should really extract data from the recip folders,
            # but how do you know which is to/cc/bcc?
            display = self._getStringStream('__substg1.0_0E04')
            self._to = display
            return display

    @property
    def cc(self):
        try:
            return self._cc
        except Exception:
            # Check header first
            if self.header is not None:
                headerResult = self.header["cc"]
                if headerResult is not None:
                    self._cc = headerResult
                    return headerResult

            # Extract from other fields
            # TODO: This should really extract data from the recip folders,
            # but how do you know which is to/cc/bcc?
            display = self._getStringStream('__substg1.0_0E03')
            self._cc = display
            return display

    @property
    def body(self):
        return self._getStringStream('__substg1.0_1000')

    @property
    def sujet(self):
        return self._getStringStream('__substg1.0_0037')

    @property
    def recupar(self):
        return self._getStringStream('__substg1.0_0040')

    @property
    def nomaffichefrom(self):
        return self._getStringStream('__substg1.0_0042')

    @property
    def Recupar(self):
        return self._getStringStream('__substg1.0_0044')

    @property
    def Lesender(self):
        return self._getStringStream('__substg1.0_0065')

    @property
    def lobjet(self):
        return self._getStringStream('__substg1.0_0070')

    @property
    def lentete(self):
        return self._getStringStream('__substg1.0_007d')

    @property
    def bcc(self):
        return self._getStringStream('__substg1.0_0E02')

    @property
    def displayto(self):
        return self._getStringStream('__substg1.0_0E04')

    def runAnalyzer(self, analyzer, data, typ):
        try:
            r = requests.post(self.cortexURL+'/api/analyzer/'+analyzer+'/run', data='{"data": "'+data+'", "attributes": {"dataType": "'+typ+'", "tlp": 0}}', headers={'Content-type': 'application/json'})
            jobId = r.json()["id"]
            while True:
                res = requests.get(self.cortexURL+'/api/job/'+jobId).json()
                if res["status"] != "InProgress":
                    return res["report"]["full"]
                time.sleep(1)
        except Exception:
            return []

    def runFileAnalyzer(self, analyzer, file):
        try:
            r = requests.post(self.cortexURL+'/api/analyzer/'+analyzer+'/run', data='{"data": " ", "attributes": {"dataType": "file", "tlp": 0, "file": "'+file+'"}}', headers={'Content-type': 'application/json'})
            jobId = r.json()["id"]
            while True:
                res = requests.get(self.cortexURL+'/api/job/'+jobId).json()
                if res["status"] != "InProgress":
                    return res["report"]["full"]
                time.sleep(1)
        except Exception:
            return []
        
    def doMISPLookup(self, value, typ):
        result = {"value": value, "events": [], "status": None, "type": typ}
        try:
            ret = self.runAnalyzer(self.MISPSearch, value, typ)
            try:
                for mispInstance in ret["results"]:
                    for event in mispInstance["result"]:
                        # get url of event
                        event["url"] = mispInstance["url"]+"/events/view/"+event["id"]
                        result["events"].append(event)
                if len(result["events"]) > 0:
                    result["status"] = True
                else:
                    result["status"] = False
            except Exception:
                pass
        except Exception:
            pass
        return result

    def processRec(self, rec):
        st = rec.replace("\r", "").replace("\n", "").replace("\t", "").replace("[", "").replace("]", "")
        r1 = re.search("from ([^\ ]*) \(([^\)]*)\)", st)
        r2 = re.search("by ([^\ ]*) \(([^\)]*)\)", st)
        r3 = re.search("; (.*)", st)
        ipRegex = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

        stat = [None, None, None, None]
        
        try:
            val = r1.group(1)
            if val:
                stat[0] = self.doMISPLookup(val, "url")
        except Exception:
            pass
        try:
            val = re.search(ipRegex, r1.group(2)).group(1)
            if val:
                stat[1] = self.doMISPLookup(val, "ip")
        except Exception:
            pass
        try:
            val = r2.group(1)
            if val:
                stat[2] = self.doMISPLookup(val, "url")
        except Exception:
            pass
        try:
            val = re.search(ipRegex, r2.group(2)).group(1)
            if val:
                stat[3] = self.doMISPLookup(val, "ip")
        except Exception:
            pass
        
        try:
            return {"from": stat[0], "fromIP":stat[1], "by": stat[2], "byIP": stat[3], "date":r3.group(1)}
        except Exception:
            return {}
        
    def getReceived(self):
    	try:
            poolA = Pool()
            resultsPoolA = [poolA.apply_async(self.processRec, (a,)) for a in self.header.get_all("Received")]
            poolA.close()
            poolA.join()
            return [r.get() for r in resultsPoolA]
        except Exception:
            return []

    def getAttachment(self, attachment):
        try:
            fname = attachment.save()
            returned = self.runFileAnalyzer(self.fileInfo, fname)
            poolB = Pool()
            resultsPoolB = [poolB.apply_async(self.doMISPLookup, (returned["Identification"][a], a,)) for a in returned["Identification"]]
            poolB.close()
            poolB.join()
            returned["Identification"] = [r.get() for r in resultsPoolB]
            returned["filename"] = attachment.longFilename
            return returned
        except Exception:
            return []

    def getAttachments(self):
        ret = []
        for a in self.attachments:
            ret.append(self.getAttachment(a))
        return ret

    def getBodyURL(self, body):
        try:
            bodyText = str(body).replace("\r", "").replace("\n", "").replace("\t", "")
            bodyURL = re.findall("((http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)", bodyText) 
            pool = Pool()
            resultsPool = [pool.apply_async(self.doMISPLookup, (a[0], "url",)) for a in bodyURL]
            pool.close()
            pool.join()
            return [r.get() for r in resultsPool]
        except Exception:
            return []

    def getReport(self, cortexURL, fileInfo, MISPSearch):
        self.cortexURL = cortexURL
        self.fileInfo = fileInfo
        self.MISPSearch = MISPSearch
        result = {"subject": str(self.subject), "date": str(self.date), "to": str(self.to), "from": str(self.sender), "cc": str(self.cc), "bcc": str(self.bcc), "body": str(self.body)}
        fields = ["X-Envelope-To", "X-Envelope-From", "X-RCPT-TO", "X-Sender", "X-Face", "X-X-Sender", "X-Originating-IP", "X-FireEye"]
        for field in fields:
            try:
                result[field] = self.header.get(field)
            except: 
                pass

        result["bodyURLs"] = self.getBodyURL(self.body)
        result["Received"] = self.getReceived()
        result["attachments"] = self.getAttachments()
        result["header"] = self.lentete

        mailid = None

        try:
            mailid = self.header["Message-ID"]
        except Exception: 
            pass

        return result