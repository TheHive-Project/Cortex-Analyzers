#!/usr/bin/env python3

# Build analyzers from Dockerfiles locally

from pathlib import Path
import docker as dockerlib
from json import loads

import asyncio

docker = dockerlib.from_env()

async def build_analyzer(analyzer):
    dockerfile = analyzer / 'Dockerfile'
    if dockerfile.exists():
        # Grab the first JSON file found-- they'll have the same docker img name anyway
        json_config = Path([x for x in analyzer.iterdir() if x.suffix == '.json'][0])
        
        if json_config.exists():
            config = loads(json_config.open().read())
            
            # If dockerImage is defined in config, use that. Else, generate
            if 'dockerImage' in config:
                image_tag = config['dockerImage']
            else:
                image_tag = 'cortexneuron/{name}:{version}'.format(
                    name=config['name'].lower(),
                    version=config['version']
                )

            dockerfile_parent_path = str(dockerfile.parent)
            # print('STRT', config['name'])
            docker.images.build(
                tag=image_tag,
                path=dockerfile_parent_path,
                forcerm=True,
            )
            # print('DONE', config['name'])


async def build_all_analyzers(analyzers):
    tasks = []
    for analyzer in analyzers:
        task = asyncio.ensure_future(build_analyzer(analyzer))
        tasks.append(task)
    
    output = await asyncio.gather(*tasks, return_exceptions=True)

    for error in [x for x in output if x]:
        print(error)


if __name__ == "__main__":
    import datetime
    start = datetime.datetime.now().isoformat()
    analyzers = [x for x in Path('..', 'analyzers').iterdir() if x.is_dir()]

    asyncio.run(build_all_analyzers(analyzers))

    print('Done!')