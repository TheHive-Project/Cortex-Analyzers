import os
from jinja2 import Environment, FileSystemLoader

class NotificationContext():
    def __init__(self, template_dir = 'templates'):
        if os.path.isdir(template_dir):
            self.template_dir = template_dir
        else:
            self.template_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir), trim_blocks=True)

    def render_blocks_to_dict(self, template_name='', kwargs=''):
        """Given a template name and kwargs, returns all blocks w/ rendered text
        Inputs:
            - template_name (str): name of template, will be appended with .j2
            - kwargs (ptr): any keyword variable from the template file
        Outputs:
            - return_dict (dict): dictionary of k,v where keys are template block names and values are the rendered
            text within each
        Example:
            rendered_dict = NotificationContext().render_blocks_to_dict(template_name=mabna,domain='bad.domain.ml')
        """
        template_path = template_name + '.j2'
        template = self.env.get_template(template_path)
        return_dict = {}
        template_ctx = template.new_context

        # render and return the jinja tmpl blocks as strings with leading/trailing whitespace stripped
        for block_name, block_text in template.blocks.items():
            return_dict[block_name] = u''.join(block_text(template_ctx(vars=kwargs))).strip()

        return return_dict
