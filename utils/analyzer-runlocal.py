#!/usr/bin/env python3

import os
import sys
import uuid
import json
import time
import subprocess
from datetime import datetime
from argparse import ArgumentParser


class AnalyzerRunlocalException(Exception):
    pass


class AnalyzerRunlocal():

    args = None

    def __init__(self):
        self.args = self.__parse_args__()

    def __parse_args__(self):
        argparse = ArgumentParser(description='Cortex Analyzer Runlocal')

        argparse.add_argument('-a', required=True, metavar="<analyzer>",
                              help="Path to the Analyzer file to be executed.")
        argparse.add_argument('-j', required=True, metavar="<jobfile>",
                              help="Path to the job definition file used to execute this Analyzer with.")
        argparse.add_argument('-p', required=False, metavar="<path>", default="/tmp/analyzer-runlocal",
                              help="Alternative path for job files (default: /tmp/analyzer-runlocal)")

        args = argparse.parse_args()
        if not args.a or not os.path.isfile(args.a) or not args.j or not os.path.isfile(args.j):
            argparse.print_help()
            print()
            exit(1)
        return args

    def main(self):
        self.stderr()

        analyzer = self.args.a.split('/')[-1]
        self.stderr('analyzer: {}'.format(analyzer))

        job_id = '{}-{}'.format(self.timestamp(), str(uuid.uuid4())[0:8])
        self.stderr('job_id:   {}'.format(job_id))

        job_path = os.path.join(self.args.p, job_id)
        self.stderr('job_path: {}'.format(job_path))

        input_path = os.path.join(job_path, 'input')
        os.makedirs(input_path)

        input_filename = os.path.join(input_path, 'input.json')
        with open(self.args.j, 'r') as f:
            job_definition = json.load(f)

        try:
            self.check_job_definition(job_definition)
        except Exception as e:
            self.stderr('\nERROR: {}\n'.format(e))
            exit(1)

        with open(input_filename, 'w') as f:
            json.dump(job_definition, f)

        command_line = '{} {}'.format(self.args.a, job_path)
        self.stderr('command:  {}'.format(command_line))

        timer_start = time.time()
        stdout, stderr, returncode = self.shell_command(command_line)
        timer_end = time.time()
        self.stderr('runtime:  {}'.format(timer_end - timer_start))
        self.stderr()

        output_filename = os.path.join(job_path,'output' ,'output.json')
        if not os.path.isfile(output_filename):
            self.stderr('\nERROR: Unable to locate expected output file {}\n'.format(output_filename))
            exit(1)

        with open(output_filename, 'r') as f:
            output = f.read()

        if returncode > 0 or stderr:
            self.stderr(stderr)
            self.stdout(output)
            exit(returncode)

        self.stdout(output)

    def check_job_definition(self, job_definition):
        if type(job_definition) is not dict:
            raise AnalyzerRunlocalException('job_definition is not a dict as expected')
        if 'dataType' not in job_definition:
            raise AnalyzerRunlocalException('job_definition is missing a "dataType" dict key value')
        if 'data' not in job_definition:
            raise AnalyzerRunlocalException('job_definition is missing a "data" dict key value')

    def stdout(self, message=''):
        print(message)

    def stderr(self, message=''):
        print(message, file=sys.stderr)

    def timestamp(self):
        return datetime.utcnow().strftime("%Y%m%dZ%H%M%S")

    def shell_command(self, command_line, timeout_seconds=300, encoding='utf8'):
        process = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait(timeout_seconds)
        stdout, stderr = process.communicate()
        if encoding is None or len(encoding) == 0:
            return stdout, stderr, process.returncode
        return (None if stdout is None else stdout.decode(encoding)), \
               (None if stderr is None else stderr.decode(encoding)), \
               process.returncode


if __name__ == '__main__':
    AnalyzerRunlocal().main()
