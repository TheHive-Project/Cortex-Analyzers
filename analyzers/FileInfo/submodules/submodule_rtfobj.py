import io
import os.path

from .submodule_base import SubmoduleBaseclass
from oletools.rtfobj import RtfObjParser, RtfObject, re_executable_extensions
from oletools import oleobj

class RTFObjectSubmodule(SubmoduleBaseclass):
    """Inspect RTF files using rtfobj which is part of oletools"""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'rtfobj'

    def check_file(self, **kwargs):
        if kwargs.get('mimetype') == 'text/rtf':
            return True
        return False

    def analyze_objects(self, path):
        data = None
        with io.open(path, 'rb') as fh:
            data = fh.read()

        parser = RtfObjParser(data)
        parser.parse()
        for idx, rtfobj in enumerate(parser.objects):
            if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                obj_type = '{} (Embedded)'.format(rtfobj.format_id)
            elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                obj_type = '{} (Linked)'.format(rtfobj.format_id)
            else:
                obj_type = '{} (Unknown)'.format(rtfobj.format_id)

            if rtfobj.is_package:
                obj_html_class = 'suspicious'
                _, ext = os.path.splitext(rtfobj.filename)
                if re_executable_extensions.match(ext):
                    obj_html_class = 'malicious'
            else:
                obj_html_class = 'info'

            if 'equation' in str(rtfobj.class_name).lower():
                obj_html_class = 'malicious'

            self.add_result_subsection(
                'Oleobject #{}'.format(idx),
                {
                    'index': '0x{:8}'.format(rtfobj.start),
                    'class': obj_html_class,
                    'type': obj_type,
                    'filename': rtfobj.filename,
                    'classname': str(rtfobj.class_name) if rtfobj.class_name else None,
                    'size': rtfobj.oledata_size
                }
            )

    def analyze_file(self, path):
        self.analyze_objects(path)
        return self.results