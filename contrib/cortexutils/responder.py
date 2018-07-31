#!/usr/bin/env python
# encoding: utf-8

import json
from cortexutils.worker import Worker


class Responder(Worker):

    def __init__(self):
        Worker.__init__(self)

        # Not breaking compatibility
        self.artifact = self._input

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""
        return self.get_param('data', None, 'Missing data field')

    @staticmethod
    def build_operation(op_type, **parameters):
        """
        :param op_type: an operation type as a string
        :param parameters: a dict including the operation's params
        :return: dict
        """
        operation = {
            'type': op_type
        }
        operation.update(parameters)

        return operation

    def operations(self, raw):
        """Returns the list of operations to be executed after the job completes

        :returns: by default return an empty array"""
        return []

    def report(self, full_report, ensure_ascii=False):
        """Returns a json dict via stdout.

        :param full_report: Responsder results as dict.
        :param ensure_ascii: Force ascii output. Default: False"""

        operation_list = []
        try:
            operation_list = self.operations(full_report)
        except Exception:
            pass

        report = {
            'success': True,
            'full': full_report,
            'operations': operation_list
        }
        json.dump(report, self.fpoutput, ensure_ascii=ensure_ascii)

    def run(self):
        """Overwritten by responders"""
        pass
