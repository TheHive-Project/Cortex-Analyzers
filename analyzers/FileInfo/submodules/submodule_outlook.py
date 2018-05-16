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
            if kwargs.get('mimetype') in ['application/vnd.ms-outlook', 'application/CDFV2-unknown']:
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
            sha256 = hashlib.sha256()
            sha256.update(attachment.data)
            a.append({'name': attachment.longFilename,
                      'sha256': sha256.hexdigest()})

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