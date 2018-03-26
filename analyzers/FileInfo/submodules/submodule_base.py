class SubmoduleBaseclass(object):
    def __init__(self):
        self.name = 'This is where the module name should go.'
        self.results = []

    def get_name(self):
        """
        Returns the name of analyzer submodule.

        :return: name
        :rtype: str
        """
        return self.name

    def check_file(self, path):
        """
        Checks if a file can be analyzed by the respective submodule.

        :return: true on success, false otherwise
        :rtype: bool
        """
        return False

    def analyze_file(self, path):
        """
        This starts the analyzation process.

        :param path: path to file
        :return:
        :rtype: dict
        """
        pass

    def add_result(self, subsection_name, value):
        """


        :param type: type of result
        :param value:
        :return:
        """
        pass

    def add_result_subsection(self, subsection_header, results):
        """
        Adding a subsection to the section of the analyzer module

        :param subsection_header: header of the subsection
        :param results: result dictionary or list
        :return:
        """
        self.results.append({
            "submodule_section_header": subsection_header,
            "submodule_section_content": results
        })
