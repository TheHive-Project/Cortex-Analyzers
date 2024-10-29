#!/usr/bin/env python3

from cortexutils.responder import Responder
import re
from urllib.parse import urlparse
import requests
import json

class JAMFProtect_IOC(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.base_url = self.get_param("config.base_url")
        self.client_id = self.get_param("config.client_id")
        self.password = self.get_param("config.password")
        self.service = self.get_param("config.service", None)
    
    def identify_and_extract(self, input_string):
        # regular expressions for different types
        patterns = {
            "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
            "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
            "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
            "ipv4": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
            "ipv6": re.compile(r"^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){1,7}|:)(:([0-9a-fA-F]{1,4}|:)){1,7}$"),
            "domain": re.compile(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*([a-zA-Z0-9-_]{2,})(\.[a-zA-Z]{2,11})$")
        }

        # check if the input_string matches any of the patterns
        for key, pattern in patterns.items():
            if pattern.match(input_string):
                return key, input_string

        # check if the input_string is a URL and extract the domain
        try:
            parsed_url = urlparse(input_string)
            if parsed_url.scheme and parsed_url.netloc:
                domain = parsed_url.netloc
                # handle URLs with "www."
                if domain.startswith("www."):
                    domain = domain[4:]
                return "domain", domain
        except Exception as e:
            self.error(f"Error parsing URL: {e}")

        return None

    def get_jamf_token(self, base_url: str, client_id: str, password: str) -> str:
        """
        Function to obtain a token from the Jamf Protect API.

        Parameters:
        - base_url (str): The base URL of your Jamf Protect instance (e.g., "https://mycompany.protect.jamfcloud.com").
        - client_id (str): The client ID for authentication.
        - password (str): The password for authentication.

        Returns:
        - str: The access token if successful, raises an exception if it fails.
        """
        token_url = f"{base_url}/token"
        headers = {'content-type': 'application/json'}
        data = {
            "client_id": client_id,
            "password": password
        }

        try:
            response = requests.post(token_url, headers=headers, data=json.dumps(data))
            response.raise_for_status()
            access_token = response.json().get('access_token')
            if access_token:
                return access_token
            else:
                raise ValueError("Failed to retrieve access token.")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to obtain token: {e}")

    def add_hash_to_prevention_list(self, base_url: str, token: str, list_name: str, description: str, hash_value: str, tags: list):
        """
        Function to add a hash to a custom prevention list in Jamf Protect using GraphQL.
        """
        graphql_url = f"{base_url}/graphql"
        headers = {
            "Authorization": f"{token}",
            "Content-Type": "application/json"
        }

        # Construct the GraphQL mutation payload
        payload = {
            "operationName": "createPreventList",
            "variables": {
                "name": list_name,
                "description": description,
                "type": "FILEHASH",
                "list": [hash_value],
                "tags": tags
            },
            "query": """
            mutation createPreventList($name: String!, $tags: [String]!, $type: PREVENT_LIST_TYPE!, $list: [String]!, $description: String) {
                createPreventList(
                    input: {name: $name, tags: $tags, type: $type, list: $list, description: $description}
                ) {
                    ...PreventListFields
                    __typename
                }
            }
            
            fragment PreventListFields on PreventList {
                id
                name
                type
                count
                list
                created
                description
                __typename
            }
            """
        }
        # Make the GraphQL request
        response = requests.post(graphql_url, headers=headers, json=payload)
        response.raise_for_status()

        result = response.json()
        if 'errors' in result:
            return f"Failed to add hash to prevention list: {result['errors']}"
        else:
            return f"Hash {hash_value} successfully added to prevention list {list_name}."

    def get_prevention_list_id(self, base_url: str, token: str, list_name: str) -> str:
        """
        Function to get the ID of a prevention list by its name.
        """
        graphql_url = f"{base_url}/graphql"
        headers = {
            "Authorization": f"{token}",
            "Content-Type": "application/json"
        }

        payload = {
            "operationName": "listPreventLists",
            "variables": {
                "nextToken": None,
                "direction": "ASC",
                "field": "created",
                "filter": None
            },
            "query": """
            query listPreventLists($nextToken: String, $direction: OrderDirection!, $field: PreventListOrderField!, $filter: PreventListFilterInput) {
                listPreventLists(
                    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100, filter: $filter}
                ) {
                    items {
                        ...PreventListFields
                        __typename
                    }
                    pageInfo {
                        next
                        total
                        __typename
                    }
                    __typename
                }
            }

            fragment PreventListFields on PreventList {
                id
                name
                type
                count
                list
                created
                description
                __typename
            }
            """
        }


        response = requests.post(graphql_url, headers=headers, json=payload)
        response.raise_for_status()

        # check if the response contains valid json data
        try:
            result = response.json()
        except ValueError as e:
            raise RuntimeError(f"Failed to decode JSON response: {e}")

        prevention_lists = result['data']['listPreventLists']['items']

        prevention_lists_ids = []
        # Search for the list with the specified name
        for prevention_list in prevention_lists:
            if prevention_list['name'] == list_name:
                prevention_lists_ids.append(prevention_list['id'])
        
        if prevention_lists_ids == []:
            raise ValueError(f"No prevention list found with name: {list_name}")
        
        return prevention_lists_ids



    def delete_prevention_list(self, base_url: str, token: str, prevent_list_ids: list):
        """
        Function to delete a prevention list in Jamf Protect using GraphQL.
        """
        graphql_url = f"{base_url}/graphql"
        headers = {
            "Authorization": f"{token}",
            "Content-Type": "application/json"
        }

        failed_deletions = []
        
        for prevent_list_id in prevent_list_ids:
            # Construct the GraphQL mutation payload
            payload = {
                "operationName": "deletePreventList",
                "variables": {
                    "id": prevent_list_id
                },
                "query": """
                mutation deletePreventList($id: ID!) {
                    deletePreventList(id: $id) {
                        id
                        __typename
                    }
                }
                """
            }

            # Make the GraphQL request
            response = requests.post(graphql_url, headers=headers, json=payload)
            response.raise_for_status()

            result = response.json()
            if 'errors' in result:
                failed_deletions.append(prevent_list_id)

        if failed_deletions:
            return f"Failed to delete prevention list(s): {', '.join(failed_deletions)}"
        
        return f"Prevention list with ID(s) {', '.join(prevent_list_ids)} successfully deleted."

    
    def run(self):
        result = ""
        observable_value = self.get_param("data.data", None)
        ioc_type, ioc_value = self.identify_and_extract(observable_value)
        if ioc_type not in ["sha256", "sha1"]:
            self.error("error -- Not a hash or a valid hash : sha1 or sha256")

        case_title = self.get_param("data.case.title", None, "Can't get case title")
        case_id = self.get_param("data.case.id", None, "Can't get case ID")
        description = f"Pushed from TheHive - {case_title} - {case_id}"

        if self.service == "addIOC":

            token = self.get_jamf_token(self.base_url, self.client_id, self.password)

            result = self.add_hash_to_prevention_list(self.base_url,token, description, description, ioc_value, ["TheHive", f"{case_id}"])      
        elif self.service == "removeIOC":
            token = self.get_jamf_token(self.base_url, self.client_id, self.password)

            prevention_list_ids = self.get_prevention_list_id(self.base_url, token, description)
            result = self.delete_prevention_list(self.base_url, token, prevention_list_ids)
        
        if 'error' in result:
           self.error(result)
        
        self.report({"message": result})
            



if __name__ == '__main__':
    JAMFProtect_IOC().run()