#!/usr/bin/env python3
import pyexifinfo
import magic
import os

from cortexutils.analyzer import Analyzer
from submodules import available_submodules
from submodules.submodule_metadata import MetadataSubmodule
from submodules.submodule_manalyze import ManalyzeSubmodule
from submodules.submodule_floss import FlossSubmodule


class FileInfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
        self.filename = self.get_param('filename', None, 'Filename is missing.')
        self.filetype = pyexifinfo.fileType(self.filepath)
        self.mimetype = magic.Magic(mime=True).from_file(self.filepath)

        # Check if manalyze submodule is enabled
        if self.get_param('config.manalyze_enable', False, 'Parameter manalyze_enable not given.'
                                                           'Please enable or disable manalyze submodule explicitly.'):
            binary_path = self.get_param('config.manalyze_binary_path',
                                         '/opt/Cortex-Analyzers/utils/manalyze/bin/manalyze')
            if self.get_param('config.manalyze_enable_docker', False):
                available_submodules.append(
                    ManalyzeSubmodule(
                        use_docker=True
                    )
                )
            elif self.get_param('config.manalyze_enable_binary', False) \
                    and os.path.isfile(binary_path):
                available_submodules.append(
                    ManalyzeSubmodule(
                        use_binary=True,
                        binary_path=binary_path
                    )
                )
            else:
                self.error('Manalyze submodule is enabled, but either there is no method allowed (docker or binary)'
                           'or the path to binary is not correct.')

        # Check if floss submodule is enabled
        if self.get_param('floss_enable', False):
            binary_path = self.get_param('floss_binary_path', None)
            if binary_path:
                available_submodules.append(
                    FlossSubmodule(
                        binary_path=binary_path,
                        string_length=self.get_param('floss_minimal_string_length', 4)
                    )
                )
            else:
                self.error('FLOSS binary path not set!')

    def summary(self, raw):
        taxonomies = []
        for submodule in raw['results']:
            taxonomies += submodule['summary']['taxonomies']
        return {'taxonomies': taxonomies}

    def run(self):
        results = []

        # Add metadata to result directly as it's mandatory
        m = MetadataSubmodule()
        metadata_results = m.analyze_file(self.filepath)
        results.append({
            'submodule_name': m.name,
            'results': metadata_results,
            'summary': m.module_summary()
        })

        for module in available_submodules:
            if module.check_file(file=self.filepath, filetype=self.filetype, filename=self.filename,
                                 mimetype=self.mimetype):
                module_results = module.analyze_file(self.filepath)
                module_summaries = module.module_summary()
                results.append({
                    'submodule_name': module.name,
                    'results': module_results,
                    'summary': module_summaries
                })

        self.report({'results': results})


if __name__ == '__main__':
    FileInfoAnalyzer().run()
