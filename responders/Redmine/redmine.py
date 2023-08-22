#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import redmine_client

class Redmine(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.instance_name = self.get_param('config.instance_name', 'redmine')
        self.instance_url = self.get_param('config.url', None, 'Missing Redmine URL')
        self.client = redmine_client.RedmineClient(
            baseurl=self.instance_url,
            username=self.get_param('config.username', None, 'Missing username'),
            password=self.get_param('config.password', None, 'Missing password'))
        self.project_field = self.get_param('config.project_field', None, 'Missing custom field for Redmine project')
        self.tracker_field = self.get_param('config.tracker_field', None, 'Missing custom field for Redmine tracker')
        self.assignee_field = self.get_param('config.assignee_field', None, 'Missing custom field for Redmine assignee')
        self.reference_field = self.get_param('config.reference_field', None)
        self.closing_task = self.get_param('config.closing_task', False)

    def run(self):
        issue_data = {}
        if self.data_type == 'thehive:case':
            issue_data = self.extract_case_data()
        elif self.data_type == 'thehive:case_task':
            issue_data = self.extract_case_data('data.case')
        else:
            self.error('Invalid dataType')
        try:
            issue = self.client.create_issue(
                title=issue_data['title'], body=issue_data['description'],
                project=issue_data['project'], tracker=issue_data['tracker'],
                status=issue_data['status'], priority=issue_data['severity'],
                assignee=issue_data['assignee'])
            self.report({
                'message': 'issue {} created'.format(issue['issue']['id']),
                'instance': {'name': self.instance_name, "url": self.instance_url},
                'issue': issue
            })
        except Exception as e:
            self.error(str(e))

    def operations(self, raw):
        ops = []
        if self.reference_field:
            ops.append(self.build_operation('AddCustomFields', name=self.reference_field, tpe='string', value='{}#{}'.format(self.instance_name, raw['issue']['issue']['id'])))
        if self.data_type == 'thehive:case_task' and self.closing_task:
            ops.append(self.build_operation('CloseTask'))
        return ops

    def extract_case_data(self, data_root='data'):
        issue_data = {}
        issue_data['title'] = self.get_param('{}.title'.format(data_root), None, 'Case title is missing')
        issue_data['description'] = self.get_param('{}.description'.format(data_root), None, 'Case description is missing')
        issue_data['severity'] = self.get_param('{}.severity'.format(data_root))
        if self.project_field:
            issue_data['project'] = self.get_param('{}.customFields.{}.string'.format(data_root, self.project_field), None, 'Project not defined in case')
        if self.tracker_field:
            issue_data['tracker'] = self.get_param('{}.customFields.{}.string'.format(data_root, self.tracker_field), None, 'Tracker not defined in case')
        if self.assignee_field:
            issue_data['assignee'] = self.get_param('{}.customFields.{}.string'.format(data_root, self.assignee_field), None)
        issue_data['status'] = self.get_param('config.opening_status')
        return issue_data

if __name__ == '__main__':
    Redmine().run()
