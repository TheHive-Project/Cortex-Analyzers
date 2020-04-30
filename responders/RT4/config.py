# Config item classes

class RT4ResponderConfig(dict):
    """Define what an RT4 Responder Config should allow and how it can be set (dict
    that only takes certain keys).
    Format courtesy of: https://stackoverflow.com/a/8187408 and https://stackoverflow.com/a/40631881

    Configs should be init'd like so: config = RT4ResponderConfig(1, **data) where 1 = weight/rank and data is a dict of k,v's
    Configs should be updated like so: config.update(1, **newdata) where 1 = weight/rank and newdata is a dict of k,v's. In this
    case, the newdata would not be entered since its weight is not greater than the existing data.
    """
    
    def __init__(self, weight=None, **kwargs):
        self.WEIGHTS = {
            'global': 1,
            'template': 2,
            'case': 3,
            'alert': 3,
            'case_artifact': 4,
            'observable': 4
        }
        self.allowed_keys = set([
            'Queue',
            'Status',
            'Owner',
            'Requestor',
            'Cc',
            'AdminCc',
            'Subject',
            'Text',
            'Priority',
            'InitialPriority',
            'FinalPriority',
            'TimeEstimated',
            'Starts',
            'Due',
            'Files',
            'template',
            'indicator_list'
        ])
        
        # 'normal' dict init, no weight but requires key_to_list_mapping
        if 'key_to_list_mapping' in kwargs:
            super().__init__(kwargs.get('key_to_list_mapping'))
        # RT4 init, be sure we have weights
        else:
            super().__init__(self)
            self.__setitem__(weight, **kwargs)


    # override default 'set' method so users can't accidentally set config items without a corresponding weight
    def __setitem__(self, weight, **kwargs):
        for key, value in kwargs.items():
            if key in self.allowed_keys or key.startswith('CF_'):
                weight_key = "{}_weight".format(key)
                # map string weight to int if needed
                if isinstance(weight, str):
                    weight = self.WEIGHTS[weight]
                if weight_key not in self or weight >= self[weight_key]:
                    # update weight key value with new weight
                    super().__setitem__(key, value)
                    super().__setitem__(weight_key, weight)
            # if we're not an RT4 setting, don't worry about weights
            # e.g., for case/artifact details we store in a config object
            else:
                super().__setitem__(key, value)

    # override default 'update' method to include weighting
    def update(self, weight, **kwargs):
        self.__setitem__(weight, **kwargs)
        
    # override default 'keys' method to only display keys related to RT4
    def keys(self):
        for key in super().keys():
            if key in self.allowed_keys:
                yield key

    # override default 'items' method to only iterate items related to RT4
    def items(self):
        for key in super().keys():
            if key in self.allowed_keys:
                yield key, self[key]

    # function to provide all items
    def fullitems(self):
        for key in super().keys():
            yield key, self[key]

    # create custom '__copy__' method. we do this so that copies don't include all the case/artifact details
    def __copy__(self):
        return self.__class__(**{'key_to_list_mapping': self.items()})

    def copy(self):
        "Returns a copy of this object."
        return self.__copy__()