"""FileInfo oletools submodule; WIP"""
from .submodule_base import SubmoduleBaseclass


class OLEToolsSubmodule(SubmoduleBaseclass):
    """Try to inspect files using python oletools."""
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'OLETools Submodule'
    
    def check_file(self, **kwargs):
        """Oletools accepts MS office documents."""
        try:
            if kwargs.get('filename').rsplit('.', 1)[1] in [
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
