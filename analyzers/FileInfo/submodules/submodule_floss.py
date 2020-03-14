import subprocess
from .submodule_base import SubmoduleBaseclass


class FlossSubmodule(SubmoduleBaseclass):
    """A module that collects string from binary."""

    def __init__(self, **kwargs):
        SubmoduleBaseclass.__init__(self)
        self.binary_path = kwargs.get("binary_path", None)
        self.name = "Floss"

    def check_file(self, **kwargs):
        """
        Floss submodule will analyze every binary data.

        :return: True
        """
        return True

    def analyze_file(self, path):

        result = []

        try:
            output = subprocess.Popen(
                [self.binary_path, path],
                stdout=subprocess.PIPE,
                universal_newlines=True,
            )
            result = [x.strip() for x in output.stdout.readlines()]
        except subprocess.CalledProcessError as e:
            results = None

        self.add_result_subsection("Floss", result)
        return self.results
