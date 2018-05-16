import hashlib
from .submodule_base import SubmoduleBaseclass

from ExtractMsg import Message, Attachment
from imapclient.imapclient import decode_utf7


class OutlookSubmodule(SubmoduleBaseclass):
    """Parse Outlook Mail and get useful information"""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'Outlook mail Information'

    def check_file(self, **kwargs):
        try:
            if kwargs.get('mimetype') == 'application/vnd.ms-outlook':
                return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):

        m = Message(path)

        def xstr(s):
            return '' if s is None else str(s)

        attachments = m.attachments
        a = []
        for attachment in attachments:
            with attachment.data as fh:
                buf = fh.read()
                sha256 = hashlib.sha256()
                sha256.update(buf)
            a.append({'name': attachment.longFilename,
                      'sha256': sha256})

        email = {'header': xstr(m.header),
                    'from': xstr(m.sender),
                    'to': xstr(m.to),
                    'cc': xstr(m.cc),
                    'subject': xstr(m.subject),
                    'date': xstr(m.date),
                    'body': decode_utf7(m.body),
                    'attachments': a
                 }
        self.add_result_subsection('Email details', email)
        return self.results