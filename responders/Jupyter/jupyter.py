#!/usr/bin/env python3
# encoding: utf-8

import nbformat
import json
import requests
import time
import datetime
import papermill as pm
from papermill.iorw import papermill_io, HttpHandler
from cortexutils.responder import Responder
from nbconvert import HTMLExporter
from tornado import gen
from tornado.escape import json_encode, json_decode, url_escape
from tornado.websocket import websocket_connect
from tornado.ioloop import IOLoop
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from uuid import uuid4


class Jupyter(Responder):
    def __init__(self):
        """Initialize the Jupyter analyzer"""
        Responder.__init__(self)

        # Initialize the ouput folder
        self.output_folder = self.get_param(
            "config.output_folder",
            None,
            "You must provide an output folder path in which executed notebooks will be stored",
        )
        today = datetime.date.today()
        # Parse the output folder to catch datetime masks
        self.output_folder = datetime.datetime.strftime(today,self.output_folder)

        # Initialize configuration objects for notebooks
        self.input_configuration = self.initialize_path(
            hostname=self.get_param(
                "config.input_hostname", None, "Hostname input parameter is missing."
            ),
            handler_http_service_api_token=self.get_param(
                "config.input_handler_http_service_api_token",
                None,
                "[HTTP Handler only] Service API token for input notebook parameter is missing.",
            ),
            handler_http_is_jupyterhub=self.get_param(
                "config.input_handler_http_is_jupyterhub",
                None,
                "[HTTP Handler only] JupyterHub for input notebook boolean parameter is missing.",
            ),
        )
        self.input_paths = self.get_param(
            "config.input_paths",
            None,
            "You must provide the list of paths of the notebooks you want to run.",
        )
        self.input_execute_remotely = self.get_param(
            "config.input_handler_http_execute_remotely",
            None,
            "You must specify if you want to run your code locally or remotely",
        )

        self.output_configuration = self.initialize_path(
            hostname=self.get_param(
                "config.output_hostname", None, "Hostname output parameter is missing."
            ),
            handler_http_service_api_token=self.get_param(
                "config.output_handler_http_service_api_token",
                None,
                "[HTTP Handler only] Service API token for output notebook parameter is missing.",
            ),
            handler_http_is_jupyterhub=self.get_param(
                "config.output_handler_http_is_jupyterhub",
                None,
                "[HTTP Handler only] JupyterHub for output notebook boolean parameter is missing.",
            ),
        )

        # Use input data as ID depending on the type
        if self.data_type == "thehive:alert":
            self.id = "alert-"+self.get_param("data", None, "Data is missing")["id"].replace("~","")
        elif self.data_type == "thehive:case":
            self.id = "case-"+self.get_param("data", None, "Data is missing")["id"].replace("~","")
        elif self.data_type == "thehive:case_artifact":
            self.id = "case-"+self.get_param("data", None, "Data is missing")["case"]["id"].replace("~","")+"-observable-"+self.get_param("data", None, "Data is missing")["id"].replace("~","")
        elif self.data_type == "thehive:case_task":
            self.id = "case-"+self.get_param("data", None, "Data is missing")["case"]["id"].replace("~","")+"-task-"+self.get_param("data", None, "Data is missing")["id"].replace("~","")
        elif self.data_type == "thehive:case_task_log":
            self.id = "case-"+self.get_param("data", None, "Data is missing")["case_task"]["case"]["id"].replace("~","")+"-task-"+self.get_param("data", None, "Data is missing")["case_task"]["id"].replace("~","")+"-log-"+self.get_param("data", None, "Data is missing")["id"].replace("~","")
        else:
            self.id = None
        # Initialize parameters
        self.parameters = {
            "thehive_organisation": str(
                self.get_param("parameters", None, "Parameters are missing")["organisation"]
            ),
            "thehive_user": str(self.get_param("parameters", None, "Parameters are missing")["user"]),
            "thehive_input_type": str(self.data_type),
            "thehive_input_value": self.get_param(
                "data", None, "Data is missing"
            ),
        }

    def initialize_path(
        self,
        hostname,
        handler_http_service_api_token=None,
        handler_http_is_jupyterhub=False,
    ):
        # Prepare result
        result = {
            "hostname": hostname,
            "handler_type": papermill_io.get_handler(hostname),
            "handler_http_service_api_token": handler_http_service_api_token,
            "handler_http_is_jupyterhub": handler_http_is_jupyterhub,
            "handler_http_headers": None,
            "handler_http_user": None,
            "server": None,
            "server_uri_http_api_contents": None,
            "server_uri_http_api_kernels": None,
            "server_uri_ws_api_kernels": None,
        }

        if result["handler_type"] is HttpHandler:
            # Build the header for authorization/authentication
            if (
                handler_http_service_api_token is not None
                and handler_http_service_api_token != ""
            ):
                result["handler_http_headers"] = {
                    "Authorization": "token " + str(handler_http_service_api_token)
                }
            else:
                # Raise an error as the service API token is missing and we are using a HTTP Handler
                self.error(
                    "[ERROR] You are using an HTTP handler but none service API token for input notebook was provided."
                )

            # Ensure other mandatory parameters are set
            user = self.get_param(
                "config.any_handler_http_user",
                None,
                "[HTTP Handler only] Service name parameter is missing.",
            )
            if user is not None and user != "":
                # Store the information
                result["handler_http_user"] = user
            else:
                # Raise an error as this parameter should be provided
                self.error(
                    "[ERROR] You are using an HTTP handler but none user was provided."
                )

            # If JupyterHub instance, then start the server first
            if handler_http_is_jupyterhub is True:
                # It's a JupyterHub instance, get the server name started
                result["server"] = self.start_server(
                    hostname,
                    result["handler_http_user"],
                    server_name="cortex_job",
                    headers=result["handler_http_headers"],
                )
                result["server_uri_http_api_contents"] = (
                    result["server"] + "api/contents"
                )
                result["server_uri_http_api_kernels"] = result["server"] + "api/kernels"
                result["server_uri_ws_api_kernels"] = result[
                    "server_uri_http_api_kernels"
                ].replace("http://", "ws://")
            else:
                # It's not a JupyterHub instance so directly the server itself
                result["server_uri_http_api_contents"] = hostname + "api/contents"
                result["server_uri_http_api_kernels"] = hostname + "api/kernels"
                result["server_uri_ws_api_kernels"] = result[
                    "server_uri_http_api_kernels"
                ].replace("http://", "ws://")

            # Initialize the ouput path
            self.create_output_path(hostname=result["server_uri_http_api_contents"],headers=result["handler_http_headers"])

        return result

    def get_conf(self, type, name):
        """This is used to recover a configuration parameter from the input or output notebooks setup

        Args:
            type (str): Indicates if the parameter type is "input" or "output"
            name (str): Name of the parameter you want to recover

        Returns:
            obj: Return the parameter value for the given type, it can be a string or an object
        """
        if type == "input":
            return self.input_configuration[name]
        elif type == "output":
            return self.output_configuration[name]
        else:
            return None

    def summary(self, raw):
        """This is used to generate short reports in TheHive

        Args:
            raw (nbformat<NotebookNode>): Notebook structure

        Returns:
            taxonomies (list): Return a list of taxonomies to be added to the observable
        """

        taxonomies = []

        for notebook in raw["notebooks"]:
            for cell in notebook["cells"]:
                if "taxonomies" in cell["metadata"]["tags"]:
                        # Get payload
                        if len(cell["outputs"]) > 0:
                            raw_observables = cell["outputs"][0]["text"].split("\n")
                            for ro in raw_observables:
                                if ro != "":
                                    try:
                                        json_taxonomy = json.loads(ro)
                                        level = json_taxonomy["level"] if "level" in json_taxonomy else "info"
                                        namespace = json_taxonomy["namespace"] if "namespace" in json_taxonomy else "Jupyter"
                                        predicate = json_taxonomy["predicate"] if "predicate" in json_taxonomy else self.error("Error: Detected taxonomy '{0}' but no predicate was given".format(json_taxonomy))
                                        value = json_taxonomy["value"] if "value" in json_taxonomy else self.error("Error: Detected taxonomy '{0}' but no value was given".format(json_taxonomy))
                                        taxonomies.append(self.build_taxonomy(level=level, namespace=namespace, predicate=predicate, value=value))
                                    except json.decoder.JSONDecodeError as e:
                                        self.error("{0} with input: {1}".format(e,ro))

        return {"taxonomies": taxonomies}
    
    def operations(self, raw):
        """This is used to execute new operations in TheHive

        Args:
            raw (nbformat<NotebookNode>): Notebook structure

        Returns:
            operations (list): Return a list of operations to be executed on the case
        """

        operations = []

        for notebook in raw["notebooks"]:
            for cell in notebook["cells"]:
                if "operations" in cell["metadata"]["tags"]:
                        # Get payload
                        if len(cell["outputs"]) > 0:
                            raw_operations = cell["outputs"][0]["text"].split("\n")
                            for ro in raw_operations:
                                if ro != "":
                                    try:
                                        json_artifact = json.loads(ro)
                                        operations.append(self.build_operation(op_type=json_artifact.pop("type"),**json_artifact))
                                    except json.decoder.JSONDecodeError as e:
                                        self.error("{0} with input: {1}".format(e,ro))
        return operations

    def event_stream(self, url, headers=""):
        """Generator yielding events from a JSON event stream

        For use with the server progress API
        """
        r = requests.get(url, headers=headers, stream=True)
        for line in r.iter_lines():
            line = line.decode("utf8", "replace")
            # event lines all start with `data:`
            # all other lines should be ignored (they will be empty)
            if line.startswith("data:"):
                yield json.loads(line.split(":", 1)[1])

    def start_server(self, hub_url, user, server_name="", headers=""):
        """Start a server for a jupyterhub user

        Returns the full URL for accessing the server
        """
        user_url = f"{hub_url}/hub/api/users/{user}"
        log_name = f"{user}/{server_name}".rstrip("/")

        # step 1: get user status
        r = requests.get(user_url, headers=headers)
        user_model = r.json()

        # if server is not 'active', request launch
        if server_name not in user_model.get("servers", {}):
            r = requests.post(f"{user_url}/servers/{server_name}", headers=headers)
            r = requests.get(user_url, headers=headers)
            user_model = r.json()

        # wait for server to be ready using progress API
        progress_url = user_model["servers"][server_name]["progress_url"]
        for event in self.event_stream(f"{hub_url}{progress_url}", headers=headers):
            if event.get("ready"):
                server_url = event["url"]
                break
        else:
            # server never ready
            raise ValueError(f"{log_name} never started!")

        # at this point, we know the server is ready and waiting to receive requests
        # return the full URL where the server can be accessed
        return f"{hub_url}{server_url}"

    def stop_server(self, hub_url, user, server_name=""):
        """Stop a server via the JupyterHub API

        Returns when the server has finished stopping
        """
        # step 1: get user status
        user_url = f"{hub_url}/hub/api/users/{user}"
        server_url = f"{user_url}/servers/{server_name}"
        log_name = f"{user}/{server_name}".rstrip("/")

        # wait for server to be done stopping
        while True:
            r = requests.get(
                user_url, headers=self.get_conf("input", "handler_http_headers")
            )
            user_model = r.json()
            if server_name not in user_model.get("servers", {}):
                return
            server = user_model["servers"][server_name]
            if not server["pending"]:
                raise ValueError(f"Waiting for {log_name}, but no longer pending.")
            # wait to poll again
            time.sleep(1)

    def create_output_path(self, hostname, headers=None):
        """This function is used to create the output path subfolders if they aren't existing yet

        Args:
            hostname (str): URL of the hostname
            headers (dict, optional): Headers for the request. Defaults to None.
        """
        subpaths = self.output_folder.split("/")
        new_path = ""
        for sp in subpaths:
            new_path += "/{0}".format(sp)
            # Build the path
            final_path = "{0}{1}".format(
                hostname,
                new_path
            )

            # Check if folder is existing
            status_code = requests.get(final_path, headers=headers).status_code
            # If the folder exists, it will return a status code 200. Otherwise, we will need to create
            if status_code != 200:
                # Create the folder
                requests.put(final_path, json={"name": sp, "type": "directory"}, headers=headers)

    @gen.coroutine
    def execute_notebook_remotely(self):
        """This function is used to execute a notebook thanks to a remote Jupyter instance using the REST API and a dedicated websocket

        Returns:
            nbformat<NotebookNode>: Output of the executed notebook
        """

        # Initialize an async HTTP client
        client = AsyncHTTPClient()

        # Execute a POST request to start a kernel (force to python3) and get the kernel id created
        response = yield client.fetch(
            self.get_conf("input", "server_uri_http_api_kernels"),
            method="POST",
            headers=self.get_conf("input", "handler_http_headers"),
            body=json_encode({"name": "python3"}),
        )
        kernel_id = json_decode(response.body)["id"]

        # Prepare the websocket request to communicate with the remote kernel
        ws_req = HTTPRequest(
            url="{}/{}/channels".format(
                self.get_conf("input", "server_uri_ws_api_kernels"),
                url_escape(kernel_id),
            ),
            headers=self.get_conf("input", "handler_http_headers"),
        )

        # Connect to websocket
        ws = yield websocket_connect(ws_req)

        # Prepare results variable
        results = []

        # Load the input notebook
        for path in iter(self.input_paths):
            nb_input = pm.iorw.load_notebook_node(
                "{0}/{1}?token={2}".format(
                    self.get_conf("input", "server_uri_http_api_contents"),
                    path,
                    self.get_conf("input", "handler_http_service_api_token"),
                )
            )

            # Parametrize the input notebook to be the output notebook
            nb_output = pm.parameterize.parameterize_notebook(
                nb_input,
                parameters=self.parameters
            )

            # Start timer
            start_time = time.time()

            # Execute the output notebooks on relevant cell_type
            for cell in iter(nb_output["cells"]):
                # Only execute cell_type equals to "code"
                if cell["cell_type"] == "code":
                    # Generate a message ID
                    msg_id = uuid4().hex

                    # Send an execute request to process the code
                    ws.write_message(
                        json_encode(
                            {
                                "header": {
                                    "username": "",
                                    "version": "5.4",
                                    "session": "",
                                    "msg_id": msg_id,
                                    "msg_type": "execute_request",
                                },
                                "parent_header": {},
                                "channel": "shell",
                                "content": {
                                    "code": cell["source"],
                                    "silent": False,
                                    "store_history": True,
                                    "user_expressions": {},
                                    "allow_stdin": False,
                                },
                                "metadata": {},
                                "buffers": {},
                            }
                        )
                    )

                    # Look for the answer by analyzing the websocket traffic
                    while 1:
                        # Get the next message
                        msg = yield ws.read_message()

                        # Parse the message
                        msg = json_decode(msg)

                        # Get interesting information
                        msg_type = msg["msg_type"]
                        parent_msg_id = msg["parent_header"]["msg_id"]

                        # Process any response from our request
                        if parent_msg_id == msg_id:
                            # Case 1: Handle error message type from the kernel
                            if msg_type == "error":
                                self.error(
                                    "ERROR - Something went wrong during the code processing. Remote kernel returns: "
                                    + str(msg)
                                )
                                break
                            # Case 2: No stdout but request done
                            elif msg_type == "execute_reply":
                                # No content*
                                cell["outputs"] = []
                                break
                            # Case 3: Stdout/stderr content detected
                            elif msg_type == "stream":
                                cell["outputs"] = [
                                    nbformat.v4.nbbase.output_from_msg(msg)
                                ]
                                break
                            # Case 4: Display data detected
                            elif msg_type == "display_data":
                                cell["outputs"] = [
                                    nbformat.v4.nbbase.output_from_msg(msg)
                                ]
                                break
                            # Otherwise, drop the message

            # Stop timer
            timer = time.time() - start_time

            # Write the notebook after execution
            # Build output path notebook
            if self.get_conf("output", "handler_type") is HttpHandler:
                output_path = "{0}/{1}/{2}-{3}?token={4}".format(
                    self.get_conf("output", "server_uri_http_api_contents"),
                    self.output_folder,
                    self.id,
                    path,
                    self.get_conf("output", "handler_http_service_api_token"),
                )
                output_path_direct = "{0}/user/{1}/tree/{2}/{3}-{4}".format(
                    self.get_conf("output", "hostname"),
                    self.get_conf("output", "handler_http_user"),
                    self.output_folder,
                    self.id,
                    path,
                )
            else:
                output_path = "{0}/{1}/{2}".format(
                    self.get_conf("output", "hostname"),
                    self.output_folder,
                    self.id,
                    path,
                )
                output_path_direct = output_path
            pm.iorw.write_ipynb(nb_output, output_path)

            # Add the timer information
            nb_output["duration"] = round(timer, 3)

            # Add the output link if we want to access it
            nb_output["output_notebook"] = output_path_direct

            # Add the name of the executed notebook
            nb_output["name"] = path

            results.append(nb_output)

        # Close the websocket once the notebook is processed
        ws.close()

        return results

    def run(self):
        """Describe the execution of the analyzer"""
        Responder.run(self)

        # Initialize an HTML exporter to render long HTML reports
        html_exporter = HTMLExporter(template_name="classic")
        # Intialize the variable to store all notebooks results
        results = []

        # Check how to execute the notebooks (local or remote)
        if (
            self.input_execute_remotely is True
            and self.get_conf("input", "handler_type") is HttpHandler
        ):
            # Execute remotely using a websocket through HTTP to communicate with the remote kernel
            results = IOLoop.current().run_sync(self.execute_notebook_remotely)

        else:
            # Execute locally through papermill

            # Loop over all the notebooks to be run
            for path in self.input_paths:
                # Build input path notebook
                if self.get_conf("input", "handler_type") is HttpHandler:
                    input_notebook = "{0}/{1}?token={2}".format(
                        self.get_conf("input", "server_uri_http_api_contents"),
                        path,
                        self.get_conf("input", "handler_http_service_api_token"),
                    )
                else:
                    input_notebook = self.get_conf("input", "hostname") + path

                # Build output path notebook
                if self.get_conf("output", "handler_type") is HttpHandler:
                    output_notebook = "{0}/{1}/{2}-{3}?token={4}".format(
                        self.get_conf("output", "server_uri_http_api_contents"),
                        self.output_folder,
                        self.id,
                        path,
                        self.get_conf("output", "handler_http_service_api_token"),
                    )
                    output_notebook_direct = "{0}/user/{1}/tree/{2}/{3}-{4}".format(
                        self.get_conf("output", "hostname"),
                        self.get_conf("output", "handler_http_user"),
                        self.output_folder,
                        self.id,
                        path,
                    )
                else:
                    output_notebook = "{0}/{1}/{2}-".format(
                        self.get_conf("output", "hostname"),
                        self.output_folder,
                        self.id,
                        path,
                    )
                    output_notebook_direct = output_notebook

                # Initialize the output notebook object result
                nb_output = None

                # Check how to execute the notebooks (local or remote)
                if (
                    self.input_execute_remotely is True
                    and self.get_conf("input", "handler_type") is HttpHandler
                ):
                    # Execute remotely using a websocket through HTTP to communicate with the remote kernel
                    results = IOLoop.current().run_sync(self.execute_notebook_remotely)

                else:
                    # Execute locally through papermill
                    # Execute the notebook
                    nb_output = pm.execute_notebook(
                        input_path=input_notebook,
                        output_path=output_notebook,
                        parameters=self.parameters,
                        request_save_on_cell_execute=False,
                        progress_bar=False,
                    )

                    # Sanitize secrets
                    nb_output["metadata"]["papermill"]["input_path"] = nb_output["metadata"]["papermill"]["input_path"].replace(
                        "?token={0}".format(
                            self.get_conf("output", "handler_http_service_api_token")
                        ),
                        "",
                    )
                    nb_output["metadata"]["papermill"]["output_path"] = nb_output["metadata"]["papermill"]["output_path"].replace(
                        "?token={0}".format(
                            self.get_conf("output", "handler_http_service_api_token")
                        ),
                        "",
                    )

                    # Duplicate duration time
                    nb_output["duration"] = round(
                        nb_output["metadata"]["papermill"]["duration"], 3
                    )

                    # Add the output link if we want to access it
                    nb_output["output_notebook"] = output_notebook_direct

                    # Add the name of the executed notebook
                    nb_output["name"] = path

                # Store the result
                results.append(nb_output)


        # Report the results
        report_results = {"notebooks": results}
        self.report(report_results)


if __name__ == "__main__":
    Jupyter().run()