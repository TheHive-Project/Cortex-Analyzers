"""FileInfo oletools submodule; WIP"""
from .submodule_base import SubmoduleBaseclass
from oletools.olevba3 import VBA_Parser, VBA_Scanner, ProcessingError


class OLEToolsSubmodule(SubmoduleBaseclass):
    """Try to inspect files using python oletools."""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'OLETools Submodule'
        self.fileextension = None

    def check_file(self, **kwargs):
        """Oletools accepts MS office documents."""
        try:
            self.fileextension = kwargs.get('filename').rsplit('.', 1)[1]
            if self.fileextension in [
                'doc',
                'docx',
                'xls',
                'xlsx',
                'ppt',
                'pptx'
            ]:
                return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):
        pass

    def analyze_vba(self, path):
        """Analyze a given sample for malicios vba."""
        try:
            parsed = VBA_Parser(path)

            if parsed.detect_vba_macros():
                for idx, (filename, stream_path, vba_filename, vba_code) in enumerate(parsed.extract_all_macros()):
                    # Decode strings often produces errors
                    scanner = VBA_Scanner(vba_code)
                    scan_results_to_report = []
                    try:
                        scan_results = scanner.scan(include_decoded_strings=True)
                    except ProcessingError:
                        scan_results = scanner.scan(include_decoded_strings=False)

                    for type, keyword, description in scan_results:
                        scan_results_to_report.append({
                            'type': type,
                            'keyword': keyword,
                            'description': description
                        })

                    self.add_result_subsection(
                        'OLE stream: {}'.format(stream_path),
                        {
                            'olevba_filename': vba_filename,
                            'olevba_code': vba_code,
                            'olevba_results': scan_results_to_report
                        }
                    )

        except TypeError:
            self.add_result_subsection('OLEVBA Analysis failed', 'Analysis failed due to an filetype error.'
                                                                 'The file does not seem to be a valid MS-Office file.')

