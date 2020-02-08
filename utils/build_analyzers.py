#!/usr/bin/env python3

# Build analyzers from Dockerfiles locally

from pathlib import Path
import subprocess
from json import loads

analyzers = [x for x in Path('..', 'analyzers').iterdir() if x.is_dir()]

for analyzer in analyzers:
    try:
        dockerfile = analyzer / 'Dockerfile'
        if dockerfile.exists():
            # Grab the first JSON file found-- they'll have the same docker img name anyway
            json_config = Path([x for x in analyzer.iterdir() if x.suffix == '.json'][0])
            
            if json_config.exists():
                config = loads(json_config.open().read())
                
                if 'dockerImage' in config:
                    image_tag = config['dockerImage']
                else:
                    image_tag = 'cortexneuron/{name}:{version}'.format(
                        name=config['name'].lower(),
                        version=config['version']
                    )

                docker_build_query = ["docker",  "build", '-t', image_tag, "--quiet",  "--force-rm"]

                if dockerfile:
                    docker_build_query += ['-f', '{}'.format(dockerfile.resolve())]

                # Specify Dockerfile parent directory as build context
                docker_build_query.append(dockerfile.parent)

                process = subprocess.run(docker_build_query, capture_output=True)

                if not process.returncode == 0:
                    print(dockerfile, 'could not be generated\n\n')
                    print(dockerfile, 'Reason:\n')
                    print(process.stderr.decode("utf-8"))



    except Exception as e:
        print(e)