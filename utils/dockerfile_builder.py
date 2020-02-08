#!/usr/bin/env python3

from pathlib import Path
import os
from json import loads

analyzers = [x for x in Path('..', 'analyzers').iterdir() if x.is_dir()]

for analyzer in analyzers:
    try:
        dockerfile_path = analyzer / 'Dockerfile'
        if dockerfile_path.exists():
            print('Updating', dockerfile_path)
        else:
            dockerfile_path.touch()
            print('Creating new docker file', dockerfile_path)
        # Grab the first JSON file found-- they _should_ have the same relevant properties anyway
        json_config = Path([x for x in analyzer.iterdir() if x.suffix == '.json'][0])
        
        if json_config.exists():

            dockerfile_contents = ["# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`\n# DO NOT EDIT IT DIRECTLY\n\n"]

            config = loads(json_config.open().read())
            process_path = Path('..', 'analyzers', config['command']).resolve()


            if 'baseImage' in config:
                dockerfile_contents.append('FROM {image}\n'.format(image=config['baseImage']))
            else:
                # Analyze source code as determined by config file
                with process_path.open() as process_src:
                    source_code = process_src.read()
                    dockerfile_contents.append("# Guessing base image from source code shebang")
                    if '#!/usr/bin/env python\n' in source_code:
                        is_python = True
                        dockerfile_contents.append('FROM python:2-alpine\n')
                    elif '#!/usr/bin/env python3\n' in source_code:
                        is_python = True
                        # If we're building every image, we should save disk space w/ alpine 
                        dockerfile_contents.append('FROM python:3-alpine\n')
                    
                    # TODO: Add more runtime shebangs! ex. go, rust, ruby

                    # Default out to ubuntu
                    else:
                        dockerfile_contents.append('FROM ubuntu\n')


            if 'name' in config:
                dockerfile_contents.append('LABEL name="{}"'.format(config['name']))

            if 'description' in config:
                dockerfile_contents.append('LABEL description="{}"'.format(config['description']))
            
            if 'author' in config:
                dockerfile_contents.append('LABEL author="{}"'.format(config['author']))



            dockerfile_contents.append('\nWORKDIR /worker')

            dockerfile_contents.append('\nCOPY . {}'.format(config['name']))


            # if python2/3 => pip install requirements.txt
            if is_python:
                dockerfile_contents.append('\n# Project determined to be Python, installing deps')
                dockerfile_contents.append('RUN pip install --no-cache-dir -r {}/requirements.txt'.format(config['name']))

            dockerfile_contents.append('\nENTRYPOINT {}'.format(config['command']))

            dockerfile_path.write_text("\n".join(dockerfile_contents))




    except Exception as e:
        import traceback
        print(traceback.format_exc(e))