#!/usr/bin/python3
from cortexutils.responder import Responder
import requests
import json
import time

STRING_TYPES = (str, bytes)
MARKDOWN_CHARS = r"\`*_{}[]()#+-!|"


def string_escape(st):
    """
       Escape any chars that might break a markdown string

       :type st: ``str``
       :param st: The string to be modified (required)

       :return: A modified string
       :rtype: ``str``
    """
    st = st.replace('\r\n', '<br>')  # Windows
    st = st.replace('\r', '<br>')  # old Mac
    st = st.replace('\n', '<br>')  # Unix

    for c in ('|', '`'):
        st = st.replace(c, '\\' + c)

    return st


def get_markdown_from_table(name, t, headers=None, headerTransform=None, url_keys=None):
    """
       Converts a JSON table to a Markdown table

       :type name: ``str``
       :param name: The name of the table (required)

       :type t: ``dict`` or ``list``
       :param t: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :type headers: ``list`` or ``string``
       :param headers: A list of headers to be presented in the output table (by order). If string will be passed
            then table will have single header. Default will include all available headers.

       :type headerTransform: ``function``
       :param headerTransform: A function that formats the original data headers (optional)

       :type url_keys: ``list``
       :param url_keys: a list of keys in the given JSON table that should be turned in to clickable

       :return: A string representation of the markdown table
       :rtype: ``str``
    """
    # Turning the urls in the table to clickable
    if url_keys:
        t = url_to_clickable_markdown(t, url_keys)

    result = ''
    if name:
        result = '### ' + name + '\n'

    if not t or len(t) == 0:
        result += '**No entries.**\n'
        return result

    if not headers and isinstance(t, dict) and len(t.keys()) == 1:
        # in case of a single key, create a column table where each element is in a different row.
        headers = list(t.keys())
        t = list(t.values())[0]

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table contains only simple objects (strings, numbers)
        # should be only one header
        if headers and len(headers) > 0:
            header = headers[0]
            t = [{header: item} for item in t]
        else:
            raise Exception(
                "Missing headers param for get_markdown_from_table. Example: headers=['Some Header']")

    # in case of headers was not provided (backward compatibility)
    if not headers:
        headers = list(t[0].keys())
        headers.sort()

    if t and len(headers) > 0:
        newHeaders = []
        if headerTransform is None:  # noqa
            def headerTransform(s): return string_escape(s.title())  # noqa
        for header in headers:
            newHeaders.append(headerTransform(header))
        result += '|'
        if len(newHeaders) == 1:
            result += newHeaders[0]
        else:
            result += '|'.join(newHeaders)
        result += '|\n'
        sep = '---'
        result += '|' + '|'.join([sep] * len(headers)) + '|\n'
        for entry in t:
            entry_copy = entry.copy()

            vals = [string_escape(str(entry_copy.get(h, '') if entry_copy.get(
                h) is not None else '')) for h in headers]

            # this pipe is optional
            result += '| '
            try:
                result += ' | '.join(vals)
            except UnicodeDecodeError:
                vals = [str(v) for v in vals]
                result += ' | '.join(vals)
            result += ' |\n'

    else:
        result += '**No entries.**\n'

    return result


def url_to_clickable_markdown(data, url_keys):
    """
    Transform the urls fields into clickable url in markdown.

    :type data: ``[Union[str, List[Any], Dict[str, Any]]]``
    :param data: a dictionary or a list containing data with some values that are urls

    :type url_keys: ``Dict[str, str]``
    :param url_keys: a dict whose keys correspond to the url fields to turn into clickable, and values correspond to the link texts

    :return: markdown format for clickable url
    :rtype: ``[Union[str, List[Any], Dict[str, Any]]]``
    """

    if isinstance(data, list):
        data = [url_to_clickable_markdown(item, url_keys) for item in data]

    elif isinstance(data, dict):
        data = {key: get_clickable_url(value, url_keys.get(key, None)) if key in url_keys else url_to_clickable_markdown(data[key], url_keys)
                for key, value in data.items()}

    return data


def get_clickable_url(url, text=None):
    """
    Make the given url clickable in markdown format

    :type url: ``Union[List[str], str]``
    :param url: the url of interest or a list of urls

    :type text: ``str``
    :param text: the link text to print

    :return: markdown format for clickable url
    :rtype: ``str``

    """
    if not url:
        return None
    elif isinstance(url, list):
        if text:
            return ['[{}]({})'.format(text, item) for item in url]
        else:
            return ['[{}]({})'.format(item, item) for item in url]

    if text:
        return '[{}]({})'.format(text, url)
    else:
        return '[{}]({})'.format(url, url)


class HarfangLab(Responder):

    def __get_first_element(self, table):
        """
           Return the first element of a table

           :type table: ``List[Any]``
           :param table: The table to extract the first element of

           :return: The first element of the table
           :rtype: ``Any``
        """

        if table and isinstance(table, list) and len(table) > 0:
            return table[0]
        else:
            return None

    def __flatten_table(self, table):
        """
           Return a flattened string of all elements of a table joined with a ','

           :type table: ``List[Any]``
           :param table: The table to flatten

           :return: The flattened table
           :rtype: ``str``
        """

        if table and isinstance(table, list) and len(table) > 0:
            return ', '.join(table)
        else:
            return None

    def __get_hash_parameter(self, binary_hash):
        """
           Return a tuple (hash filter name, hash value) to be used as filter for the HarfangLab API

           :type binary_hash: ``str``
           :param str: The raw binary hash (either MD5, SHA1 or SHA256)

           :return: A tuple (hash filter name, hash value)
           :rtype: ``Tuple(str,str)``
        """

        hash_type = None
        if binary_hash is not None:
            if len(binary_hash) == 64:
                hash_type = "sha256"
            elif len(binary_hash) == 40:
                hash_type = "sha1"
            elif len(binary_hash) == 32:
                hash_type = "md5"

            return (f'hashes.{hash_type}', binary_hash)

        return (None, None)

    def __generate_link_for_binary(self, v):
        """
           Return a HarfangLab download link for a binary including a temporary api token

           :type v: ``str``
           :param v: The binary SHA256 hash

           :return: A download link
           :rtype: ``str``
        """

        url = f'{self.apiURL}/api/user/api_token/'
        api_token = None

        try:
            token = self.hlSession.post(
                url=url, data={'is_expirable': True}).json()
            if 'api_token' in token:
                api_token = token['api_token']
            link = f'{self.apiURL}/api/data/telemetry/Binary/download/{v}'
            if api_token:
                link += f'?hl_expiring_key={api_token}'
            return link

        except Exception as e:
            return 'N/A'

    def __generate_link_for_artifact(self, v):
        """
           Return a HarfangLab download link for a job artifact from its id

           :type v: ``str``
           :param v: The artifact id

           :return: A download link
           :rtype: ``str``
        """

        url = f'{self.apiURL}/api/user/api_token/'
        api_token = None

        try:
            token = self.hlSession.post(
                url=url, data={'is_expirable': True}).json()
            if 'api_token' in token:
                api_token = token['api_token']
            link = f'{self.apiURL}/api/data/investigation/artefact/Artefact/{v}/download/'
            if api_token:
                link += f'?hl_expiring_key={api_token}'

            return link
        except Exception as e:
            return 'N/A'

    def __get_destination_ip(self, v):
        """
           Return a tuple (hash filter name, hash value) to be used as filter for the HarfangLab API for a destination IP filter

           :type v: ``str``
           :param v: The IP address

           :return: A tuple (hash filter name, hash value)
           :rtype: ``Tuple(str,str)``
        """

        return ('daddr', v)

    def __get_source_ip(self, v):
        """
           Return a tuple (hash filter name, hash value) to be used as filter for the HarfangLab API for a source IP filter

           :type v: ``str``
           :param v: The IP address

           :return: A tuple (hash filter name, hash value)
           :rtype: ``Tuple(str,str)``
        """
        return ('saddr', v)

    def __get_kill_process_api_endpoint(self):
        """
           Return the HarfangLab API endpoint to kill a specific process from its UUID

           :return: The API endpoint
           :rtype: ``str``
        """
        if not self.processUUID: 
            self.error(f'Missing process unique identifier field: "hfl/process/process_unique_id')
            return None
        return f'/api/data/telemetry/Processes/{self.processUUID}/requestKillProcess/'

    def __get_dump_process_api_endpoint(self):
        """
           Return the HarfangLab API endpoint to dump a specific process from its UUID

           :return: The API endpoint
           :rtype: ``str``
        """
        if not self.processUUID: 
            self.error(f'Missing process unique identifier field: "hfl/process/process_unique_id')
            return None
        return f'/api/data/telemetry/Processes/{self.processUUID}/requestDumpProcess/'

    """
    The JOBS dict contains all the job services and their description. Its keys correspond to the service names in the service description file in JSON format.
    Each job is associated to a responder flavor. When called from a TheHive case, it generates a dedicated task in TheHive whose description contains the job result in Markdown.

    Job description structure:
      * request_api_endpoint: HarfangLab API endpoint to start a job and get its status
      * result_api_endpoint: HarfangLab API endpoint to get job results
      * title: Title associated to the job result, that is provided in the task description
      * task_title: Description of the TheHive task
      * action: Job action that is transmitted to the HarfangLab API
      * ordering: Value ordering field (format corresponding to HarfangLab API)
      * fields: List of output fields to provide in the resulting markdown table.

    Each output field is described with the following parameters:
      * name: Name of the field as provided in the result table headers
      * path: Path of the field value for extraction from the job results. The path is composed of all dict keys separated by a '.'
      * default: Default value to use if the path does not exist
      * transform: Function to use to transform the field before inserting into the resulting table
      * is_url: Indicates whether the field must be rendered as a markdown URL
      * link_text: Corresponds to the link text to show if the field must be rendered as a markdown URL. It not specified, the URL will be used as the text to show.
    """

    JOBS = {
        'getProcesses': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Process/',
            'title': 'Process list',
            'task_title': 'Review process list',
            'action': 'getProcessList',
            'ordering': 'name',
            'fields': [
                {'name': 'name', 'path': 'name', 'default': None},
                {'name': 'session', 'path': 'session', 'default': None},
                {'name': 'username', 'path': 'username', 'default': None},
                {'name': 'integrity', 'path': 'integrity_level', 'default': None},
                {'name': 'pid', 'path': 'pid', 'default': None},
                {'name': 'ppid', 'path': 'ppid', 'default': None},
                {'name': 'cmdline', 'path': 'cmdline', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getServices': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Service/',
            'title': 'Service list',
            'task_title': 'Review service list',
            'action': 'getHives',
            'ordering': 'service_name',
            'fields': [
                {'name': 'name', 'path': 'service_name', 'default': None},
                {'name': 'image path', 'path': 'image_path', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getPipes': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Pipe/',
            'title': 'Pipe list',
            'task_title': 'Review pipe list',
            'action': 'getPipeList',
            'ordering': 'name',
            'fields': [
                    {'name': 'name', 'path': 'name', 'default': None}
            ]
        },
        'getDrivers': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Driver/',
            'title': 'Loaded driver list',
            'task_title': 'Review loaded driver list',
            'action': 'getLoadedDriverList',
            'ordering': 'short_name',
            'fields': [
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getPrefetches': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Prefetch/',
            'title': 'Prefetch list',
            'task_title': 'Review prefetch list',
            'action': 'getPrefetch',
            'ordering': '-last_executed',
            'fields': [
                {'name': 'executable name',
                        'path': 'executable_name', 'default': None},
                {'name': 'last executed', 'path': 'last_executed',
                 'default': None, 'transform': __get_first_element},
            ]
        },
        'getScheduledTasks': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/ScheduledTaskXML/',
            'title': 'Scheduled task list',
            'task_title': 'Review scheduled task list',
            'action': 'getScheduledTasks',
            'ordering': 'short_name',
            'fields': [
                {'name': 'name', 'path': 'short_name', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getRunKeys': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/RunKey/',
            'title': 'Run key list',
            'task_title': 'Review run key list',
            'action': 'getHives',
            'ordering': '-last_executed',
            'fields': [
                {'name': 'name', 'path': 'short_name', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getStartupFiles': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Startup/',
            'title': 'Startup file list',
            'task_title': 'Review startup file list',
            'action': 'getStartupFileList',
            'ordering': 'filename',
            'fields': [
                {'name': 'startup file name',
                        'path': 'filename', 'default': None},
                {'name': 'startup file full path',
                 'path': 'fullpathfilename', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
                {'name': 'signed', 'path': 'binaryinfo.binaryinfo.signed',
                 'default': False},
                {'name': 'md5', 'path': 'binaryinfo.binaryinfo.md5', 'default': None},
                {'name': 'sha1', 'path': 'binaryinfo.binaryinfo.sha1',
                 'default': None},
                {'name': 'sha256', 'path': 'binaryinfo.binaryinfo.sha256',
                 'default': None}
            ]
        },
        'getPersistence': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/PersistanceFile/',
            'title': 'Persistence list',
            'task_title': 'Review persistence list',
            'action': 'persistanceScanner',
            'ordering': 'short_name',
            'fields': [
                {'name': 'type', 'path': 'persistance_type', 'default': None},
                {'name': 'filename', 'path': 'binaryinfo.filename', 'default': None},
                {'name': 'fullpath', 'path': 'binaryinfo.fullpath', 'default': None},
            ]
        },
        'getWMI': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Wmi/',
            'title': 'WMI list',
            'task_title': 'Review  list',
            'action': 'getWMI',
            'ordering': 'filename',
            'fields': [
                {'name': 'filter to consumer type',
                        'path': 'filtertoconsumertype', 'default': None},
                {'name': 'event filter name',
                 'path': 'eventfiltername', 'default': None},
                {'name': 'event consumer name',
                 'path': 'eventconsumername', 'default': None},
                {'name': 'event filter', 'path': 'eventfilter', 'default': None},
                {'name': 'consumer data', 'path': 'consumerdata', 'default': None},
            ]
        },
        'getNetworkShares': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/NetworkShare/',
            'title': 'Network share list',
            'task_title': 'Review network share list',
            'action': 'getNetworkShare',
            'ordering': 'name',
            'fields': [
                {'name': 'name', 'path': 'name', 'default': None},
                {'name': 'caption', 'path': 'caption', 'default': None},
                {'name': 'description', 'path': 'description', 'default': None},
                {'name': 'path', 'path': 'path', 'default': None},
                {'name': 'status', 'path': 'status', 'default': None},
                {'name': 'share type val',
                 'path': 'sharetypeval', 'default': None},
                {'name': 'share type', 'path': 'sharetype', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
            ]
        },
        'getSessions': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/hunting/Session/',
            'title': 'Session list',
            'task_title': 'Review session list',
            'action': 'getSessions',
            'ordering': 'name',
            'fields': [
                {'name': 'logon id', 'path': 'logonid', 'default': None},
                {'name': 'authentication package',
                 'path': 'authenticationpackage', 'default': None},
                {'name': 'logon type', 'path': 'logontype', 'default': None},
                {'name': 'logon type str',
                 'path': 'logontypestr', 'default': None},
                {'name': 'session start time',
                 'path': 'sessionstarttime', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
            ]
        },
        'getArtifactMFT': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'MFT',
            'task_title': 'Analyze MFT',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': False, 'mft': True,
                           'prefetch': False, 'usn': False, 'logs': False, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactHives': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'Hives',
            'task_title': 'Analyze Hives',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': True, 'evt': False, 'mft': False,
                           'prefetch': False, 'usn': False, 'logs': False, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactEvtx': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'Windows event logs',
            'task_title': 'Analyze event logs',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': True, 'mft': False,
                           'prefetch': False, 'usn': False, 'logs': False, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactLogs': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'Linux logs',
            'task_title': 'Analyze logs',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': False, 'mft': False,
                           'prefetch': False, 'usn': False, 'logs': True, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactFilesystem': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'Linux filesystem',
            'task_title': 'Analyze filesystem',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': False, 'mft': False,
                           'prefetch': False, 'usn': False, 'logs': False, 'fs': True},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactUSN': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'USN logs',
            'task_title': 'Analyze USN logs',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': False, 'mft': False,
                           'prefetch': False, 'usn': True, 'logs': False, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactPrefetch': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'USN logs',
            'task_title': 'Analyze prefetches',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': False, 'evt': False, 'mft': False,
                           'prefetch': True, 'usn': False, 'logs': False, 'fs': False},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactAll': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'All raw artifacts',
            'task_title': 'Analyze all raw artifacts',
            'action': 'collectRAWEvidences',
            'parameters': {'hives': True, 'evt': True, 'mft': True,
                           'prefetch': True, 'usn': True, 'logs': True, 'fs': True},
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'getArtifactRamdump': {
            'request_api_endpoint': '/api/data/Job/',
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'RAM Dump',
            'task_title': 'Analyze RAM dump',
            'action': 'memoryDumper',
            'ordering': 'name',
            'fields': [
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'killProcess': {
            'request_api_endpoint': __get_kill_process_api_endpoint,
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/job/Simple/',
            'title': 'Killed process',
            'task_title': 'Review process kill report',
            'action': 'knownProcessFinderKiller',
            'ordering': 'name',
            'fields': [
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'date', 'path': 'date', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None}
            ]
        },
        'dumpProcess': {
            'request_api_endpoint': __get_dump_process_api_endpoint,
            'status_api_endpoint': '/api/data/Job/',
            'result_api_endpoint': '/api/data/investigation/artefact/Artefact/',
            'title': 'Dumped process',
            'task_title': 'Analyze dumped process',
            'action': 'processDumper',
            'ordering': '-date',
            'fields': [
                {'name': 'message', 'path': 'msg', 'default': None},
                {'name': 'date', 'path': 'date', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'download_link', 'path': 'id', 'default': None,
                 'transform': __generate_link_for_artifact, 'is_url': True, 'link_text': 'Download'}
            ]
        },
    }


    TELEMETRY_SEARCHES = {
        'searchHash': {
            'api_endpoint': '/api/data/telemetry/Processes/',
            'title': 'Hash search',
            'task_title': 'Review hash search in telemetry',
            'inputs': [
                {'name': 'hash', 'filter': 'hash',
                 'transform': __get_hash_parameter, 'mandatory': True},
                {'name': 'process_name', 'filter': 'process_name'},
                {'name': 'image_name', 'filter': 'image_name'},
                {'name': 'limit', 'filter': 'limit'}
            ],
            'fields': [
                {'name': 'name', 'path': 'name', 'default': None},
                {'name': 'creation date',
                 'path': '@event_create_date', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'process name', 'path': 'process_name', 'default': None},
                {'name': 'image name', 'path': 'image_name', 'default': None},
                {'name': 'command line', 'path': 'commandline', 'default': None},
                {'name': 'integrity level',
                 'path': 'integrity_level', 'default': None},
                {'name': 'parent image', 'path': 'parent_image', 'default': None},
                {'name': 'parent command line',
                 'path': 'parent_commandline', 'default': None},
                {'name': 'username', 'path': 'username', 'default': None},
                {'name': 'signed', 'path': 'signed', 'default': None},
                {'name': 'signer', 'path': 'signature_info.signer_info.display_name',
                 'default': None},
                {'name': 'md5', 'path': 'hashes.md5', 'default': None},
                {'name': 'sha1', 'path': 'hashes.sha1', 'default': None},
                {'name': 'sha256', 'path': 'hashes.sha256', 'default': None}
            ]
        },
        'getBinary': {
            'api_endpoint': '/api/data/telemetry/Binary/',
            'title': 'Binary download',
            'task_title': 'Analyze binary',
            'inputs': [
                {'name': 'hash', 'filter': 'hash',
                 'transform': __get_hash_parameter, 'mandatory': True}
            ],
            'fields': [
                {'name': 'path', 'path': 'paths', 'default': None,
                 'transform': __flatten_table},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'signed', 'path': 'signed', 'default': None},
                {'name': 'signer', 'path': 'signature_info.signer_info.display_name',
                 'default': None},
                {'name': 'md5', 'path': 'hashes.md5', 'default': None},
                {'name': 'sha1', 'path': 'hashes.sha1', 'default': None},
                {'name': 'sha256', 'path': 'hashes.sha256', 'default': None},
                {'name': 'download_link', 'path': 'hashes.sha256', 'default': None,
                 'transform': __generate_link_for_binary, 'is_url': True, 'link_text': 'Download'}
            ]
        },
        'searchSourceIP': {
            'api_endpoint': '/api/data/telemetry/Network/',
            'title': 'IP search',
            'task_title': 'Review Source IP search in telemetry',
            'inputs': [
                {'name': 'ip', 'filter': 'saddr',
                 'transform': __get_source_ip, 'mandatory': True},
                {'name': 'limit', 'filter': 'limit'}
            ],
            'fields': [
                {'name': 'creation date',
                 'path': '@event_create_date', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'image name', 'path': 'image_name', 'default': None},
                {'name': 'username', 'path': 'username', 'default': None},
                {'name': 'source address', 'path': 'saddr', 'default': None},
                {'name': 'source port', 'path': 'sport', 'default': None},
                {'name': 'destination address',
                 'path': 'daddr', 'default': None},
                {'name': 'destination port', 'path': 'dport', 'default': None},
                {'name': 'direction', 'path': 'direction', 'default': None},
            ]
        },
        'searchDestinationIP': {
            'api_endpoint': '/api/data/telemetry/Network/',
            'title': 'IP search',
            'task_title': 'Review Destination IP search in telemetry',
            'inputs': [
                {'name': 'ip', 'filter': 'daddr',
                 'transform': __get_destination_ip, 'mandatory': True},
                {'name': 'limit', 'filter': 'limit'}
            ],
            'fields': [
                {'name': 'creation date',
                 'path': '@event_create_date', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'image name', 'path': 'image_name', 'default': None},
                {'name': 'username', 'path': 'username', 'default': None},
                {'name': 'source address', 'path': 'saddr', 'default': None},
                {'name': 'source port', 'path': 'sport', 'default': None},
                {'name': 'destination address',
                 'path': 'daddr', 'default': None},
                {'name': 'destination port', 'path': 'dport', 'default': None},
                {'name': 'direction', 'path': 'direction', 'default': None},
            ]
        },
        'searchDriverByFileName': {
            'api_endpoint': '/api/data/telemetry/DriverLoad/',
            'title': 'Driver load search',
            'task_title': 'Review driver load search in telemetry',
            'inputs': [
                {'name': 'filename', 'filter': 'imagename', 'manatory': True}
            ],
            'fields': [
                {'name': 'loading time', 'path': '@timestamp', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'image name', 'path': 'imagename', 'default': None},
                {'name': 'image path', 'path': 'imagepath', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'signed', 'path': 'signed', 'default': None},
                {'name': 'signer', 'path': 'signature_info.signer_info.display_name',
                 'default': None},
                {'name': 'md5', 'path': 'hashes.md5', 'default': None},
                {'name': 'sha1', 'path': 'hashes.sha1', 'default': None},
                {'name': 'sha256', 'path': 'hashes.sha256', 'default': None}
            ]
        },
        'searchDriverByHash': {
            'api_endpoint': '/api/data/telemetry/DriverLoad/',
            'title': 'Driver load search',
            'task_title': 'Review driver load search in telemetry',
            'inputs': [
                {'name': 'hash', 'filter': 'hash',
                 'transform': __get_hash_parameter, 'mandatory': True},
            ],
            'fields': [
                {'name': 'loading time', 'path': '@timestamp', 'default': None},
                {'name': 'hostname', 'path': 'agent.hostname', 'default': None},
                {'name': 'image name', 'path': 'imagename', 'default': None},
                {'name': 'image path', 'path': 'imagepath', 'default': None},
                {'name': 'size', 'path': 'size', 'default': None},
                {'name': 'signed', 'path': 'signed', 'default': None},
                {'name': 'signer', 'path': 'signature_info.signer_info.display_name',
                 'default': None},
                {'name': 'md5', 'path': 'hashes.md5', 'default': None},
                {'name': 'sha1', 'path': 'hashes.sha1', 'default': None},
                {'name': 'sha256', 'path': 'hashes.sha256', 'default': None}
            ]
        }

    }
#                'ioc': '/api/data/investigation/ioc/IOC/',

    def __init__(self):
        Responder.__init__(self)
        self.apiURL = self.get_param(
            'config.apiURL', None, 'API URL is missing!')
        self.apiKey = self.get_param(
            'config.apiKey', None, 'API Key is missing!')
        self.limit = self.get_param('config.limit', 100)
        self.jobTimeout = int(self.get_param('config.jobTimeout', 600))

        if self.apiURL:
            self.apiURL = self.apiURL.rstrip('/')

        self.data = self.get_param('data', None, 'data is missing!')
        self.observable = self.data.get('data')
        self.observable_type = self.data.get('dataType')

        if self.data_type == 'thehive:case_task':
            self.agentId = self.get_param('data.case.customFields', {
            }, 'Case custom fields are missing').get('hfl/agent/agentid', {}).get('string', None)
            self.agentHostname = self.get_param('data.case.customFields', {
            }, 'Case custom fields are missing').get('hfl/agent/hostname', {}).get('string', None)
        elif self.data_type == 'thehive:case' or self.data_type == 'thehive:alert':
            self.agentId = self.get_param('data.customFields', {}, 'Case custom fields are missing').get(
                'hfl/agent/agentid', {}).get('string', None)
            self.agentHostname = self.get_param('data.customFields', {}, 'Case custom fields are missing').get(
                'hfl/agent/hostname', {}).get('string', None)
            self.processUUID = self.get_param('data.customFields', {}, 'Case custom fields are missing').get(
                'hfl/process/process_unique_id', {}).get('string', None)

        self.service = self.get_param(
            "config.service", None, 'Service is missing')

        self.hlSession = requests.Session()
        self.hlSession.headers.update(
            {
                'Authorization': f'Token {self.apiKey}'
            }
        )

    def run(self):
        """
           Function used by Cortex to run the responder

           :return: A tuple (hash filter name, hash value)
           :rtype: ``Tuple(str,str)``
        """

        Responder.run(self)

        def search_telemetry(service_name, args):
            """
               Search in HarfangLab telemetry and returns a markdown table with the search results

               :type args: ``Dict[str, str]``
               :param args: The arguments for the telemetry search (ip, hash, filename...)

               :return: A dict with the results with the following keys: 'message' (message associated to the operation), 'output' (the JSON table with the results), 'markdown' (the markdown table). 
               :rtype: ``Dict[str,Any]``
            """

            result = {}
            result['message'] = 'Failed'
            result['markdown'] = ''

            serv = None
            if service_name in HarfangLab.TELEMETRY_SEARCHES:
                serv = HarfangLab.TELEMETRY_SEARCHES[service_name]
            else:
                return

            url = f'{self.apiURL}{serv["api_endpoint"]}'

            params = {}

            for field in serv['inputs']:
                func = field.get('transform', None)
                data = args.get(field['name'], None)
                mandatory = field.get('mandatory', False)
                if not data and mandatory:
                    self.error(
                        f'Mismatch between the observable type and what the responder expects ({field["name"]})')
                    return
                if func:
                    (f, v) = func(self, data)
                    params[f] = v
                elif data:
                    params[field['filter']] = data

            try:
                response = self.hlSession.get(url=url, params=params)
                response.raise_for_status()
            except Exception as e:
                self.error(f'Failed to search in telemetry %s' % (str(e)))
                return
            response = response.json()
            output = []
            url_keys = {}
            for x in response['results']:
                res = {}
                for f in serv['fields']:
                    k = f['name']
                    if 'is_url' in f:
                        url_keys[f['name']] = f.get('link_text', None)
                    tokens = f['path'].split('.')
                    v = x
                    for t in tokens:
                        if v:
                            v = v.get(t, None)
                        else:
                            v = f['default']
                    func = None
                    if 'transform' in f.keys():
                        func = f.get('transform')
                        v = func(self, v)
                    res[k] = v

                output.append(res)

            result['message'] = 'OK'
            result['output'] = output

            headers = []
            for h in serv['fields']:
                headers.append(h['name'])

            result['markdown'] += f'### {serv["title"]}\n\n'
            result['markdown'] += f'#### Search parameters\n\n'
            result['markdown'] += get_markdown_from_table(
                None, args, headers=args.keys())
            result['markdown'] += f'#### Results ({len(output)} entries)\n\n'
            result['markdown'] += get_markdown_from_table(
                None, output, headers=headers, url_keys=url_keys)
            return result

        def run_job(job_name):
            """
               Run a HarfangLab job and returns a markdown table with the results

               :type job_name: ``str``
               :param job_name: The job name from the JOBS description to trigger

               :return: A dict with the results with the following keys: 'message' (message associated to the operation), 'output' (the JSON table with the results), 'markdown' (the markdown table). 
               :rtype: ``Dict[str,Any]``
            """

            result = {}
            result['message'] = 'Failed'
            result['markdown'] = ''

            job = None
            if job_name in HarfangLab.JOBS:
                job = HarfangLab.JOBS[job_name]
            else:
                self.error('Unknown service')
                return

            if not self.agentId:
                self.error('Not agent identifier found. It must be in a case or alert custom field "hfl/agent/agentid".')
                return

            # Create job
            api_endpoint = None
            if isinstance(job["request_api_endpoint"],str):
                api_endpoint = job["request_api_endpoint"]
            elif callable(job["request_api_endpoint"]):
                func = job["request_api_endpoint"]
                api_endpoint = func(self)
            if not api_endpoint:
                return

            url = f'{self.apiURL}{api_endpoint}'

            data = {
                'targets': {'agents': [self.agentId]},
                'actions': [
                    {
                        'value': job.get('action', None),
                        'params': job.get('parameters', None),
                    }
                ]
            }

            try:
                response = self.hlSession.post(url=url, json=data)
                response.raise_for_status()
                data = response.json()
                if isinstance(data,list):
                    if len(data) == 0:
                        self.error(
                            'Failed to start job (wrong agent identifier ?)')
                        return
                    job_id = data[0]['id']
                elif isinstance(data,dict):
                    job_id = data['job_id']

            except Exception as e:
                self.error('Failed to start job: %s' % (str(e)))
                return

            # Get job status
            url = f'{self.apiURL}{job["status_api_endpoint"]}{job_id}'

            duration = 0
            polling_period = 5

            while duration < self.jobTimeout*60:
                try:
                    response = self.hlSession.get(url=url)
                    response.raise_for_status()
                    info = response.json()
                except Exception as e:
                    self.error('Failed to get job status: %s' % (str(e)))
                    return

                status = "running"

                if info['instance'] == info['done']:
                    status = "finished"
                elif info['error'] > 0:
                    status = "error"
                elif info['canceled'] > 0:
                    status = "canceled"
                elif info['waiting'] > 0:
                    status = "waiting"
                elif info['running'] > 0:
                    status = "running"
                elif info['injecting'] > 0:
                    status = "injecting"

                if status in ['error', 'canceled']:
                    result['message'] = 'Job execution failed'
                    result['markdown'] = 'Job execution failed'
                    return result
                if status == 'finished':
                    time.sleep(polling_period)
                    break
                time.sleep(polling_period)
                duration += polling_period

            # Get Job results
            url = f'{self.apiURL}{job["result_api_endpoint"]}?limit=10000&job_id={job_id}'

            if job['ordering'] is not None:
                url += f'&ordering={job["ordering"]}'

            try:
                response = self.hlSession.get(url=url)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                self.error('Failed to get job results: %s' % (str(e)))
                return

            output = []
            url_keys = {}
            for x in data['results']:
                res = {}
                for f in job['fields']:
                    k = f['name']
                    if 'is_url' in f:
                        url_keys[f['name']] = f.get('link_text', None)

                    tokens = f['path'].split('.')
                    v = x
                    for t in tokens:
                        if v:
                            v = v.get(t, None)
                        else:
                            v = f['default']
                    func = None
                    if 'transform' in f.keys():
                        func = f.get('transform')
                        v = func(self, v)
                    res[k] = v

                output.append(res)

            result['message'] = 'OK'
            result['output'] = output

            headers = []
            for h in job['fields']:
                headers.append(h['name'])
            result['markdown'] = get_markdown_from_table(
                job['title'], output, headers=headers, url_keys=url_keys)
            return result

        if self.service == "isolateEndpoint":
            '''
            Isolate and endpoint
            '''
            url = f'{self.apiURL}/api/data/endpoint/Agent/{self.agentId}/isolate/'

            if not self.agentId:
                self.error(
                    'No agent Id found in the case or alert description')
                return

            try:
                response = self.hlSession.post(url=url)
                if response.status_code != 200:
                    self.error(
                        f'Failed to isolate host {self.agentHostname}: {response.status_code} ({response.reason})')
                    return
                else:
                    """
                    Isolation has successfully been requested. We need to check that the policy allows isolation.
                    """
                    if len(response.json().get('policy_not_allowed', [])) > 0:
                        self.error(
                            f'Unable to isolate host {self.agentHostname} since isolation is not allowed in the policy.')
                        return

                    """
                    Isolation has successfully been requested and policy allows isolation. We need to check when isolation is effective.
                    """
                    polling_period = 2
                    sleep_time = 60

                    duration = 0
                    while duration < sleep_time:

                        url = f'{self.apiURL}/api/data/endpoint/Agent/{self.agentId}/'
                        response = self.hlSession.get(url=url)
                        if response.status_code != 200:
                            self.error(
                                f'Failed to get agent\'s status for host {self.agentHostname}: {response.status_code} ({response.reason})')
                            return
                        else:
                            sleep_time = int(response.json().get(
                                'policy', {}).get('sleeptime', 60))*2
                            isolation_state = response.json().get('isolation_state')

                            if isolation_state:
                                self.report(
                                    {'message': f'Host {self.agentHostname} successfully isolated'})
                                return
                            else:
                                duration += polling_period
                                time.sleep(polling_period)
                    self.error(
                        f'Host isolation successfully requested but host never switched to an isolated state...')

            except requests.exceptions.RequestException as e:
                self.error(e)

        elif self.service == "unisolateEndpoint":
            '''
            Unisolate and endpoint
            '''
            url = f'{self.apiURL}/api/data/endpoint/Agent/{self.agentId}/deisolate/'

            if not self.agentId:
                self.error(
                    'No agent Id found in the case or alert description')
                return

            try:
                response = self.hlSession.post(url=url)
                if response.status_code != 200:
                    self.error(
                        f'Failed to unisolate host {self.agentHostname}: {response.status_code} ({response.reason})')
                    return
                else:

                    """
                    Unisolation has successfully been requested. We need to check when unisolation is effective.
                    """
                    polling_period = 2
                    sleep_time = 60

                    duration = 0
                    while duration < sleep_time:

                        url = f'{self.apiURL}/api/data/endpoint/Agent/{self.agentId}/'
                        response = self.hlSession.get(url=url)
                        if response.status_code != 200:
                            self.error(
                                f'Failed to get agent\'s status for host {self.agentHostname}: {response.status_code} ({response.reason})')
                            return
                        else:
                            sleep_time = int(response.json().get(
                                'policy', {}).get('sleeptime', 60))*2
                            isolation_state = response.json().get('isolation_state')

                            if not isolation_state:
                                self.report(
                                    {'message': f'Host {self.agentHostname} successfully unisolated'})
                                return
                            else:
                                duration += polling_period
                                time.sleep(polling_period)
                    self.error(
                        f'Host unisolation successfully requested but host never switched to an unisolated state...')

            except requests.exceptions.RequestException as e:
                self.error(e)

        elif self.service in HarfangLab.JOBS:
            output = run_job(self.service)
            self.report(output)

        elif self.service in HarfangLab.TELEMETRY_SEARCHES:
            args = {}
            args['limit'] = self.limit
            if self.observable_type == 'hash':
                args['hash'] = self.observable
            elif self.observable_type == 'ip':
                args['ip'] = self.observable
            elif self.observable_type == 'filename':
                args['filename'] = self.observable
            output = search_telemetry(self.service, args)
            self.report(output)

        else:
            self.error('Unidentified service')

    def operations(self, raw):
        """
           Provide a list of operations TheHive must execute when getting the responder results

           :type raw: ``Dict[str, Any]``
           :param raw: The raw result of the responder provided by the run function

           :return: A tuple a list of operations
           :rtype: ``List[Any]``
        """

        if self.service == "isolateEndpoint":
            return [self.build_operation("AddTagToCase", tag="HarfangLab:isolated")]
        elif self.service == "unisolateEndpoint":
            return [self.build_operation("AddTagToCase", tag="HarfangLab:unisolated")]
        elif self.service in HarfangLab.JOBS:
            return [self.build_operation("CreateTask", title=HarfangLab.JOBS.get(self.service).get('task_title', ''), description=raw.get('markdown'))]
        elif self.service in HarfangLab.TELEMETRY_SEARCHES:
            return [self.build_operation("CreateTask", title=HarfangLab.TELEMETRY_SEARCHES.get(self.service).get('task_title', ''), description=raw.get('markdown'))]


if __name__ == '__main__':

    HarfangLab().run()
