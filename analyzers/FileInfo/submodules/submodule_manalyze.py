import subprocess
import json
import os
from .submodule_base import SubmoduleBaseclass


class ManalyzeSubmodule(SubmoduleBaseclass):
    """Manalyze submodule implements the static analysis tool by @JusticeRage
    (https://github.com/JusticeRage/Manalyze)"""

    def __init__(self, **kwargs):
        SubmoduleBaseclass.__init__(self)

        self.use_docker = kwargs.get('use_docker', False)
        self.use_binary = kwargs.get('use_binary', False)
        self.binary_path = kwargs.get('binary_path', None)

    def check_file(self, **kwargs):
        """
        Manalyze is for PE files.
        """
        try:
            if kwargs.get('filetype') in ['Win32 EXE', 'Win64 EXE']:
                return True
        except KeyError:
            return False
        return False

    def run_local_manalyze(self, filepath):
        sp = subprocess.Popen([
            self.binary_path,
            '--dump=imports,exports,sections',
            '--hashes',
            '--pe {}'.format(filepath),
            '--plugins=clamav,compilers,peid,strings,findcrypt,btcaddress,packer,imports,resources,mitigation,authenticode',
            '--output json'
        ], subprocess.PIPE, cwd=os.path.split(self.binary_path)[0])
        result = sp.communicate()
        result = json.loads(result)
        return result[0]

    def run_docker_manalyze(self, filepath):
        filepath, filename = os.path.split(filepath)
        sp = subprocess.Popen([
            'docker',
            'run',
            '--rm',
            '-v',
            '{}:/data'.format(filepath),
            'evanowe/manalyze',
            '/Manalyze/bin/manalyze',
            '--dump=imports,exports,sections',
            '--hashes',
            '--pe /data/{}'.format(filename),
            '--plugins=clamav,compilers,peid,strings,findcrypt,btcaddress,packer,imports,resources,mitigation,authenticode',
            '--output json'
        ], subprocess.PIPE)
        result = sp.communicate()
        result = json.loads(result)
        return result[0]

    def analyze_file(self, path):
        if self.use_docker:
            self.add_result_subsection('Manalyze (Docker)', self.run_docker_manalyze(path))
        elif self.use_binary and self.binary_path and self.binary_path != '':
            self.add_result_subsection('Manalyze (Binary)', self.run_local_manalyze(path))
        return self.results
