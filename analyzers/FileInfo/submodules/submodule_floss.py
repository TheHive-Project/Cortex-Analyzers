import subprocess
from .submodule_base import SubmoduleBaseclass
from os.path import isfile, exists


class FlossSubmodule(SubmoduleBaseclass):
    def __init__(self, **kwargs):
        SubmoduleBaseclass.__init__(self)
        self.name = 'FLOSS'
        self.floss_path = kwargs.get('binary_path', None)
        self.string_length = kwargs.get('string_length', 4)

    def check_file(self, **kwargs):
        """FLOSS can be used for any kind of file, but stack strings only work for PEs."""
        return True

    def run_floss(self, filepath) -> str:
        """Run the floss binary

        :returns: Raw string output"""
        if not exists(self.floss_path) or not isfile(self.floss_path):
            return 'ERROR:floss:FLOSS binary not found.'
        sp = subprocess.run([
            self.floss_path,
            '-n {}'.format(self.string_length),
            filepath
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = sp.stdout.decode('utf-8')
        stderr = sp.stderr.decode('utf-8')
        return '{}\n{}'.format(stdout, stderr)

    def process_output(self, output: str) -> dict:
        """Processes the output string and return a dictionary with sections to use in the build results method.
        :param output: str
        :returns: dict"""
        processed_output = {}
        lines = output.split('\n')
        current_section = 'No section set'
        for line in lines:
            if line[:24] == 'Finished execution after':
                continue
            if (line[0:5] == 'FLOSS' and line[-7:] == 'strings') or line[0:12] == 'ERROR:floss:':
                if line[0:12] == 'ERROR:floss:':
                    current_section = 'Errors'
                else:
                    current_section = line
                if current_section not in processed_output.keys():
                    processed_output.update({current_section: []})
                continue

            if line != '':
                if line[0:12] == 'ERROR:floss:':
                    processed_output[current_section].append(line[12:])
                else:
                    processed_output[current_section].append(line)
        return processed_output

    def build_results(self, results: dict):
        for section, strings in results.items():
            self.add_result_subsection(section, strings)

    def analyze_file(self, path):
        self.build_results(self.process_output(self.run_floss(path)))
        return self.results
