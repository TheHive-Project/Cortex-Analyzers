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

    def run(self):
        if self.data_type == 'thehive:case':
            title = self.get_param('data.title', None, 'title is missing')
            description = self.get_param('data.description', None, 'description is missing')
            project = None
            tracker = None
            assignee = None
            if self.project_field:
                project = self.get_param('data.customFields.{}.string'.format(self.project_field), None, 'Project not defined in case')
            if self.tracker_field:
                tracker = self.get_param('data.customFields.{}.string'.format(self.tracker_field), None, 'Tracker not defined in case')
            if self.assignee_field:
                assignee = self.get_param('data.customFields.{}.string'.format(self.assignee_field), None)
            try:
                issue = self.client.create_issue(
                    title=title, body=description, project=project, tracker=tracker,
                    status=self.get_param('config.opening_status'), priority=self.get_param('data.severity'),
                    assignee=assignee)
                self.report({
                    'message': 'issue {} created'.format(issue['issue']['id']),
                    'instance': {'name': self.instance_name, "url": self.instance_url}, 
                    'issue': issue
                })
            except Exception as e:
                self.error(str(e))
        else:
            self.error('Invalid dataType')

if __name__ == '__main__':
    Redmine().run()
