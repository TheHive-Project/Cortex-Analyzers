class SubmoduleBaseclass(object):
    def __init__(self):
        self.name = 'This is where the module name should go.'
        self.results = []
        self.summary = {'taxonomies': []}

    def get_name(self):
        """
        Returns the name of analyzer submodule.

        :return: name
        :rtype: str
        """
        return self.name

    def build_taxonomy(self, level, namespace, predicate, value):
        """
        :param level: info, safe, suspicious or malicious
        :param namespace: Name of analyzer
        :param predicate: Name of service
        :param value: value
        :return: dict
        """
        return {
                'level': level,
                'namespace': namespace,
                'predicate': predicate,
                'value': value
                }

    def check_file(self, **kwargs):
        """
        Checks if a file can be analyzed by the respective submodule. This can be done using the file-parameter or the
        filetype-parameter (fileType() of pyexiftool). Submodules can choose how to check, if a file fits their analysis
        method.
        If this returns true, the analyze_file() function gets called.

        :param file: used for checking compatibility for a file directly.
        :type file: str
        :param filetype: used for checking compatibility for a file using the filetype string of pyexiftool.fileType().
        :type filetype: str
        :param filename: the original filename, not the one given by cortex
        :type filename: str
        :return: true on success, false otherwise
        :rtype: bool
        """
        return False

    def analyze_file(self, path):
        """
        This starts the analyzation process. Depends on the return value of check_file().

        :param path: path to file
        :return:
        :rtype: dict
        """
        return {}


    def module_summary(self):
        """
        Build summary info for a submodule from its reports. Should be defined in each submodule that needs to show minireports

        :return:
        :rtype: dict
        """
        return self.summary

    def add_result_subsection(self, subsection_header, results):
        """
        Adding a subsection to the section of the analyzer module

        :param subsection_header: header of the subsection
        :param results: result dictionary or list
        :param summary: result dictionary
        :return:
        """
        self.results.append({
            "submodule_section_header": subsection_header,
            "submodule_section_content": results
        })
