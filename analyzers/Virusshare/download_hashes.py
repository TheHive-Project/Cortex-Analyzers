#!/usr/bin/env python
"""This script downloads all available Virusshare.com hash files. The user-agent is set to Chrome 57. It can be called
as:

./download_hashes.py PATH

or quiet as:

./download_hashes -q PATH
"""
import io
import progressbar
import re
import requests
import os
import sys

URL = 'https://virusshare.com/hashes/VirusShare_00'


def run(path, quiet=False):
    """
    Downloads all available hash files to a given path.
    
    :param path: Path to download directory
    :param quiet: If set to True, no progressbar is displayed
    """
    if os.path.isdir(path):
        session = requests.Session()
        session.headers = {'User-agent': 'Mozilla/5.0 Chrome/57.0.2987.110'}
        max_num = max(list(map(int, re.sub(r'[\<\>]',
                                           '',
                                           '\n'.join(re.findall(r'\>[1-9][0-9]{2}\<',
                                                                session.get('https://virusshare.com/hashes.4n6').text
                                                                )
                                                     )
                                           ).split('\n')
                               )
                           )
                      )
        if not quiet:
            p = progressbar.ProgressBar(max_value=max_num)
        for i in range(max_num):
            filename = str(i).zfill(3) + '.md5'
            if os.path.exists(os.path.join(path, filename)):
                continue
            if not quiet:
                p.update(i)
            url = URL + filename
            head = session.head(url)
            if head.status_code == 200:
                body = session.get(url, stream=True)
                with io.open(os.path.join(path, str(i).zfill(3) + '.md5'), mode='wb') as afile:
                    for chunk in body.iter_content(chunk_size=1024):
                        afile.write(b'' + chunk)
                body.close()
    else:
        print('Given path is not a directory.')
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        run(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] == '-q':
        run(sys.argv[2], quiet=True)
    else:
        print('No path given')
        sys.exit(1)
