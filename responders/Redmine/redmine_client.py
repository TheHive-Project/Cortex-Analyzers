import requests

class RedmineClient:
    def __init__(self, baseurl, username, password):
        self.base_url = baseurl
        self.session = requests.Session()
        self.session.headers.update({'content-type': 'application/json'})
        self.session.auth = (username, password)

    def create_issue(self, title=None, body=None, project=None, tracker=None,
                     priority=None, status=None, assignee=None):
        payload = {
            'issue': {
                'subject': title,
                'description': body,
                'project_id': project,
                'tracker_id':  self.get_tracker_id(tracker),
                'priority_id': priority,
                'status_id':   self.get_status_id(status),
                'assigned_to_id': self.get_assignee_id(project, assignee)
            }
        }
        url = self.base_url + '/issues.json'
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        if 'error' in result:
            raise RedmineClientError(result['error'])
        return result

    def get_tracker_id(self, name):
        url = self.base_url + '/trackers.json'
        id = None
        trackers = self.session.get(url)
        trackers.raise_for_status()
        for p in trackers.json()['trackers']:
            if p['name'] == name:
                id = p['id']
                break
        return id

    def get_status_id(self, name):
        url = self.base_url + '/issue_statuses.json'
        id = None
        issue_statuses = self.session.get(url)
        issue_statuses.raise_for_status()
        for p in issue_statuses.json()['issue_statuses']:
            if p['name'] == name:
                id = p['id']
                break
        return id

    def get_assignee_id(self, project, assignee):
        url = '{}/projects/{}/memberships.json'.format(self.base_url, project)
        id = None
        payload = {'offset': 0}
        total_count = 0
        while id is None and payload['offset'] <= total_count:
            response = self.session.get(url, params=payload)
            response.raise_for_status()
            for member in response.json()['memberships']:
                if 'user' in member:
                    if assignee == member['user']['name']:
                        id = member['user']['id']
                        break
                elif 'group' in member:
                    if assignee == member['group']['name']:
                        id = member['group']['id']
                        break
            total_count = response.json()['total_count']
            payload['offset'] += response.json()['limit']
        return id


class RedmineClientError(Exception):
    def __init__(self, message):
        self.message = message
