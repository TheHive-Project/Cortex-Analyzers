#!/usr/bin/env python3

import subprocess
from pathlib import Path
from sys import argv
from json import loads

class BuildErr(BaseException):
    def __init__(self):
        pass


success_msg = '{"success": false, "input": {}, "errorMessage": "Input file doesnt exist"}'

config_required_msg="""  File "/usr/local/lib/python3.8/site-packages/cortexutils/worker.py", line 31, in __init__
    self._input = json.load(sys.stdin)
  File "/usr/local/lib/python3.8/json/__init__.py", line 293, in load
    return loads(fp.read(),
  File "/usr/local/lib/python3.8/json/__init__.py", line 357, in loads
    return _default_decoder.decode(s)
  File "/usr/local/lib/python3.8/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/usr/local/lib/python3.8/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
"""

if __name__ == "__main__":

    root = Path(argv[0]).absolute().parent.parent

    analyzers_path = Path(root, 'analyzers')
    
    for analyzer_path in sorted([x for x in analyzers_path.iterdir() if x.is_dir()]):
        dockerfile_path = analyzer_path / 'Dockerfile'
        if dockerfile_path.exists():
            name = build_hash = exec_proc = None
            try:

                name = analyzer_path.stem
                print('Running:\x1b[96m\x1b[1m', name, '\x1b[39m\x1b[0m')
                build_proc = subprocess.run(['docker', 'build', '-t', 'test_build', '--rm', '-q', analyzer_path], capture_output=True)

                if not build_proc.returncode == 0:
                    print('\t\x1b[31mBuild failed!', name, '\x1b[39m')
                    print(build_proc.stderr.decode('utf-8'))
                    raise BuildErr()

                build_hash = build_proc.stdout.decode('utf-8').rstrip()
                
                exec_proc = subprocess.run(["docker", "run", "--rm", "-it", build_hash], capture_output=True)
                
                output = exec_proc.stdout.decode('utf-8').rstrip()
                err = exec_proc.stderr.decode('utf-8').rstrip()
                # On success, expect all analyzers to output "Input file doesnt exist" errmessage
                
                print(output)
                print(err)

                if exec_proc.returncode == 1:

                    if success_msg in output:
                        print('\t\x1b[32mSuccess!!!\x1b[39m')
                    else:
                        print('\x1b[31m', output,'\x1b[39m')

                else:
                    print('\x1b[31m', output,'\x1b[39m')

            # Allow force quit
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            
            # On err go to next
            except:

                continue
            finally:
                # Cleanup
                if build_hash:
                    rmi_proc = subprocess.run(['docker', 'rmi', build_hash], capture_output=True)

                    if rmi_proc.returncode == 0:
                        print('\t\x1b[90mImage removed successfully\x1b[39m')
                
