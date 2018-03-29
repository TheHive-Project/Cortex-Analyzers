from .submodule_oletools import OLEToolsSubmodule
from .submodule_pe import PESubmodule

available_submodules = [
    PESubmodule(),
    OLEToolsSubmodule()
]
