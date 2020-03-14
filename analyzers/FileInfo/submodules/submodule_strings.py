import sys
import string
from .submodule_base import SubmoduleBaseclass


def strings(path, min=5):
    with open(path, "rb") as f:
        res = ""
        for c in f.read():
            if sys.version[0] == '2':
                if c in string.printable:
                    res += c
                    continue
                if len(res) >= min:
                    yield res
                res = ""
            else:
                if chr(c) in string.printable:
                    res += chr(c)
                    continue
                if len(res) >= min:
                    yield res
                res = ""
        if len(res) >= min: 
            yield res


class StringsSubmodule(SubmoduleBaseclass):
    """A module that collects string from binary."""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'strings'

    def check_file(self, **kwargs):
        """
        strings submodule will analyze every binary data.

        :return: True
        """
        return True

    def analyze_file(self, path):
        result = [x for x in strings(path)]
        self.add_result_subsection('strings', result)
        return self.results
