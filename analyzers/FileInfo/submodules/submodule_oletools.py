"""FileInfo oletools submodule; WIP"""
from .submodule_base import SubmoduleBaseclass
from oletools.oleid import OleID
from oletools.olevba3 import VBA_Parser, VBA_Scanner, ProcessingError
from oletools.msodde import process_file


class OLEToolsSubmodule(SubmoduleBaseclass):
    """Try to inspect files using python oletools."""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'Oletools Submodule'

    def check_file(self, **kwargs):
        """Oletools accepts MS office documents."""

        try:
            if kwargs.get('filetype') in [
                'DOC',
                'DOCM',
                'DOCX',
                'XLS',
                'XLSM',
                'XLSX',
                'PPT',
                'PPTM',
                'PPTX'
            ]:
                return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):
        # Run the analyze functions
        self.analyze_oleid(path)
        self.analyze_vba(path)
        self.analyze_dde(path)

        return self.results

    def analyze_oleid(self, path):
        indicators = OleID(path).check()
        results = {}

        for indicator in indicators:
            if indicator.id == 'appname':
                continue
            results.update({indicator.name: indicator.value})
        self.add_result_subsection('Oletools OleID Results', results)

    def analyze_vba(self, path):
        """Analyze a given sample for malicios vba."""
        try:
            parser = VBA_Parser(path)

            if parser.detect_vba_macros():
                for idx, (filename, stream_path, vba_filename, vba_code) in enumerate(parser.extract_all_macros()):
                    # Decode strings often produces errors or gibberish
                    scan_results = VBA_Scanner(vba_code).scan(include_decoded_strings=False)
                    scan_results_to_report = []

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
                            'olevba_code': vba_code.decode('unicode-escape'),
                            'olevba_results': scan_results_to_report
                        }
                    )

        except TypeError:
            self.add_result_subsection('Oletools VBA Analysis failed', 'Analysis failed due to an filetype error.'
                                                                 'The file does not seem to be a valid MS-Office file.')

    def analyze_dde(self, path):
        results = process_file(path)
        if len(results) > 0:
            self.add_result_subsection('Oletools DDE Analysis', {'DDEUrl': results})
        else:
            self.add_result_subsection('Oletools DDE Analysis', {'Info': 'No DDE URLs found.'})
