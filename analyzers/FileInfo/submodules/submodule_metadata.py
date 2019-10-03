import magic
import hashlib
import io
import os
import pyexifinfo

from .submodule_base import SubmoduleBaseclass
from ssdeep import Hash


class MetadataSubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'Basic properties'

    def check_file(self, **kwargs):
        """
        Metadata submodule will analyze every file, therefore it will always return true.

        :return: True
        """
        return True

    def exif(self, path):
        # Exif info
        exifreport = pyexifinfo.get_json(path)
        result = dict((key, value) for key, value in exifreport[0].items() if
                      not (key.startswith("File") or key.startswith("SourceFile")))
        return result

    def module_summary(self):
        taxonomy = {'level': 'info', 'namespace': 'FileInfo', 'predicate': 'Filetype', 'value': ''}
        taxonomies = []

        for section in self.results:
            if section['submodule_section_header'] == 'File information':
                t = taxonomy
                t['value'] = section['submodule_section_content']['Filetype']
                taxonomies.append(t)
            else:
                pass

        self.summary['taxonomies'] = taxonomies
        return self.summary

    def analyze_file(self, path):
        # Hash the file
        with io.open(path, 'rb') as fh:
            buf = fh.read()
            md5 = hashlib.md5()
            md5.update(buf)
            sha1 = hashlib.sha1()
            sha1.update(buf)
            sha256 = hashlib.sha256()
            sha256.update(buf)
            ssdeep = Hash()
            ssdeep.update(buf)

        self.add_result_subsection('Hashes', {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
            'ssdeep': ssdeep.digest()
        })

        self.add_result_subsection('Exif Info', self.exif(path))

        # Get libmagic info
        magicliteral = magic.Magic(mime_encoding=True).from_file(path)
        mimetype = magic.Magic(mime=True,mime_encoding=True).from_file(path)
        # filetype = pyexifinfo.fileType(path)


        self.add_result_subsection('File information', {
            'Magic literal': magicliteral,
            'MimeType': mimetype,
            'Filetype': pyexifinfo.fileType(path),
            'Filesize': os.path.getsize(path)}
                                   )

        return self.results
