#!/usr/bin/env python3

from pathlib import Path
import os
from json import loads

analyzers = [x for x in Path('..', 'analyzers').iterdir() if x.is_dir()]

for analyzer in analyzers:
    try:
        dockerfile_path = analyzer / 'Dockerfile'

        update = dockerfile_path.exists()

        if update:
            with dockerfile_path.open() as dockerfile:
                dockerfile = dockerfile.read()

                # Dockerfiles with this string will be frozen; skip.
                if '### MANUAL ###' in dockerfile:
                    continue
            
        else:
            dockerfile_path.touch()
            print('Creating new docker file', dockerfile_path)
        # Grab the first JSON file found-- they _should_ have the same relevant properties anyway
        json_config = Path([x for x in analyzer.iterdir() if x.suffix == '.json'][0])
        
        if json_config.exists():

            dockerfile_contents = ["### AUTOGEN ###\n# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`\n# DO NOT EDIT IT DIRECTLY\n"]

            config = loads(json_config.open().read())
            process_path = Path('..', 'analyzers', config['command']).resolve()

            # Determine baseImage for Dockerfile
            if 'baseImage' in config:
                baseImage = config['baseImage']
            else:
                # Analyze source code as determined by config file
                with process_path.open() as process_src:
                    source_code = process_src.read()
                    dockerfile_contents.append("# Guessing base image from source code shebang")
                    if '#!/usr/bin/env python\n' in source_code:
                        # If we're building every image, we should save disk space w/ alpine
                        baseImage = 'python:2-alpine'
                        is_python = is_alpine = True
                    elif '#!/usr/bin/env python3\n' in source_code:
                        # If we're building every image, we should save disk space w/ alpine
                        baseImage = 'python:3-alpine'
                        is_python = is_alpine = True
                    
                    # TODO: Add more runtime shebangs! ex. go, rust, ruby

                    # Default out to ubuntu
                    else:
                        baseImage = 'ubuntu'

            dockerfile_contents.append('FROM {}\n'.format(baseImage))


            # Include alpine-specific dependencies
            if is_alpine:

                # Using a set to prevent duplicate install operations
                alpine_dependencies = set()
                if is_python:
                    requirements_path = analyzer / 'requirements.txt'
                    if requirements_path.exists():
                        requirements = requirements_path.open().read()
                        
                        if 'yara-python' in requirements:
                            alpine_dependencies.add('gcc')
                            alpine_dependencies.add('musl-dev')
                        if 'python-magic' in requirements:
                            alpine_dependencies.add('libmagic')
                        if 'eml_parser' in requirements:
                            alpine_dependencies.add('libmagic')
                            alpine_dependencies.add('g++')

                        # One of the requirements is a git repository-- include git
                        if 'git+https' in requirements:
                            alpine_dependencies.add('git')
                else:
                    # TODO: Add more language support here
                    pass


                if alpine_dependencies:
                    dockerfile_contents.append('RUN apk add --no-cache {}\n'.format(' '.join(sorted(alpine_dependencies))))


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

            if update and dockerfile != "\n".join(dockerfile_contents):
                print("Updating", dockerfile_path)
                dockerfile_path.write_text("\n".join(dockerfile_contents))




    except Exception as e:
        import traceback
        print(traceback.format_exc(e))