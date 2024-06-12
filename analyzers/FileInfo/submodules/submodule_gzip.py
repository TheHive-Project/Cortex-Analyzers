from .submodule_base import SubmoduleBaseclass


class GZIPSubmodule(SubmoduleBaseclass):
    """This is just for showing how to include a submodule. No real functionality here."""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = "GZIP Test"

    def check_file(self, **kwargs):
        if kwargs.get("filetype") == "GZIP":
            return True
        return False

    def analyze_file(self, path):
        self.add_result_subsection("TEST", {})
        return self.results, None
