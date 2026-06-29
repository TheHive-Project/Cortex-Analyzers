import os
import re
import hashlib
import magic
import tempfile
from .submodule_base import SubmoduleBaseclass

#  from ExtractMsg import Message, Attachment
from extract_msg import Message, Attachment
from imapclient.imapclient import decode_utf7


def _safe_attachment_filename(raw_name):
    """Reduce an attachment name to a safe basename, or None if unusable."""
    if not raw_name or "\x00" in raw_name:
        return None
    # normalise Windows separators first; "\" is not a separator on POSIX
    base = os.path.basename(raw_name.replace("\\", "/"))
    if not base or base in (".", "..") or os.path.isabs(base) or re.match(r"^[A-Za-z]:", base):
        return None
    return base


class OutlookSubmodule(SubmoduleBaseclass):
    """Parse Outlook Mail and get useful information"""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = "Outlook mail Information"

    def check_file(self, **kwargs):
        try:
            msg_mimetypes = ["application/vnd.ms-outlook", "application/CDFV2-unknown"]
            for m in msg_mimetypes:
                if kwargs.get("mimetype").find(m) == 0:
                    return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):

        m = Message(path)

        def xstr(s):
            return "" if s is None else str(s)

        attachments = m.attachments
        a = []
        observables = []
        outdir = tempfile.mkdtemp()
        for attachment in attachments:
            sha256 = hashlib.sha256()
            if type(attachment.data) is not Message:
                sha256.update(attachment.data)
                minfo = magic.Magic(uncompress=True).from_buffer(attachment.data)
                a.append(
                    {
                        "name": attachment.longFilename,
                        "sha256": sha256.hexdigest(),
                        "mimeinfo": minfo,
                    }
                )
                filename = _safe_attachment_filename(attachment.longFilename) or \
                    "attachment_{}".format(sha256.hexdigest()[:16])
                filepath = os.path.join(outdir, filename)
                if not os.path.realpath(filepath).startswith(
                    os.path.realpath(outdir) + os.sep
                ):
                    continue
                with open(filepath, "wb") as f:
                    f.write(attachment.data)
                    observables.append(filepath)

        email = {
            "header": xstr(m.header),
            "from": xstr(m.sender),
            "to": xstr(m.to),
            "cc": xstr(m.cc),
            "subject": xstr(m.subject),
            "date": xstr(m.date),
            "body": decode_utf7(m.body),
            "attachments": a,
        }
        self.add_result_subsection("Email details", email)
        return self.results, observables
