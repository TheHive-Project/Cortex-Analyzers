#!/usr/bin/env python3
from cortexutils.responder import Responder
import json
import grpc
import re
import os
import time
import yaml
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc


class Velociraptor(Responder):
  def __init__(self):
    Responder.__init__(self)
    self.configpath = self.get_param('config.velociraptor_client_config', None, "File path missing!")
    self.config = yaml.load(open(self.configpath).read(), Loader=yaml.FullLoader)
    self.artifact = self.get_param('config.velociraptor_artifact', None, 'Artifact missing!')
    self.upload_flow_results = self.get_param('config.upload_flow_results', None, 'Upload decision missing!')
    self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
    self.observable = self.get_param('data.data', None, 'Data missing!')
    self.thehive_url = self.get_param('config.thehive_url', None, "TheHive URL missing!")
    self.thehive_apikey = self.get_param('config.thehive_apikey', None, "TheHive API key missing!")
    
  def run(self):
    Responder.run(self)
    case_id = self.get_param('data._parent')
    creds = grpc.ssl_channel_credentials(
        root_certificates=self.config["ca_certificate"].encode("utf8"),
        private_key=self.config["client_private_key"].encode("utf8"),
        certificate_chain=self.config["client_cert"].encode("utf8")
    )

    options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)

    with grpc.secure_channel(self.config["api_connection_string"],
                             creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)

        if self.observable_type == "ip":
            client_query = "select client_id from clients() where last_ip =~ '"+ self.observable  + "'"    
        elif re.search(r'fqdn|other', self.observable_type):
            client_query = "select client_id from clients(search='host:" + self.observable + "')"
        else:
            self.report({'message': "Not a valid data type!" })
            return
      
        # Send initial request
        client_request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            Query=[api_pb2.VQLRequest(
                Name="TheHive-ClientQuery",
                VQL=client_query,
            )])

        for client_response in stub.Query(client_request):
          try:
            client_results = json.loads(client_response.Response)
            global client_id
            client_id = client_results[0]['client_id']
          except:
              self.report({'message': 'Could not find a suitable client.'})
              pass

        # Define initial query
        init_query = "SELECT collect_client(client_id='"+ client_id +"',artifacts=['" + self.artifact + "']) FROM scope()"

        # Send initial request
        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            Query=[api_pb2.VQLRequest(
                Name="TheHive-Query",
                VQL=init_query,
            )])

        for response in stub.Query(request):
          try:
            init_results = json.loads(response.Response)
            flow=list(init_results[0].values())[0]
            
            flow_id = str(flow['flow_id']) 
            # Define second query
            flow_query = "SELECT * from flows(client_id='" + str(flow['request']['client_id']) + "', flow_id='" + flow_id + "')"
         
            state=0

            # Check to see if the flow has completed        
            while (state != 2):
    
              followup_request = api_pb2.VQLCollectorArgs(
                max_wait=10,
                Query=[api_pb2.VQLRequest(
                     Name="TheHive-QueryForFlow",
                     VQL=flow_query,
                )])

              for followup_response in stub.Query(followup_request):
                try:
                    flow_results = json.loads(followup_response.Response)
                except:
                  pass
              state = flow_results[0]['state']
              global artifact_results
              artifact_results = flow_results[0]['artifacts_with_results']
              self.report({'message': state })
              if state == 2:
                time.sleep(5)
                break

            # Grab the source from the artifact
            source_results=[]
            for artifact in artifact_results:
              source_query="SELECT * from source(client_id='"+ str(flow['request']['client_id']) + "', flow_id='" + flow_id +  "', artifact='" + artifact + "')"
              source_request = api_pb2.VQLCollectorArgs(
              max_wait=10,
              Query=[api_pb2.VQLRequest(
                  Name="TheHive-SourceQuery",
                  VQL=source_query,
              )])
              for source_response in stub.Query(source_request):
                try:
                  source_result = json.loads(source_response.Response)
                  source_results += source_result
                except:
                  pass
            self.report({'message': source_results })
            
            if self.upload_flow_results is True: 
              # Create flow download
              vfs_query = "SELECT create_flow_download(client_id='"+ str(flow['request']['client_id']) + "', flow_id='" + str(flow['flow_id']) +  "', wait='true') as VFSPath from scope()" 
              vfs_request = api_pb2.VQLCollectorArgs(
                max_wait=10,
                Query=[api_pb2.VQLRequest(
                    Name="TheHive-VFSQuery",
                    VQL=vfs_query,
              )])
              for vfs_response in stub.Query(vfs_request):
                  try:
                    vfs_result = json.loads(vfs_response.Response)[0]['VFSPath']
                  except:
                    pass
              # "Artifact" plugin.
              offset = 0
            
              file_request = api_pb2.VFSFileBuffer(
                  vfs_path=vfs_result,
                  length=10000,
                  offset=offset,
              )

              res = stub.VFSGetBuffer(file_request)
              
              if len(res.data) == 0:
                 break
                   
 
         
              f = open("/tmp/" + self.artifact + "_" + client_id + "_" + flow_id + "_" + case_id + ".zip",'wb')
              f.write(res.data)
              offset+=len(res.data)
 
              #Upload file to TheHive
              api = TheHiveApi(self.thehive_url, self.thehive_apikey, cert=False)

              description = "Velociraptor flow for artifact" + self.artifact + "for client " + client_id + " via flow " + flow_id + "." 
              filepath = '/tmp/' + self.artifact + "_" + client_id + "_" + flow_id + "_" + case_id + ".zip"
              file_observable = CaseObservable(dataType='file',
                   data=[filepath],
                   tlp=self.get_param('data.tlp'),
                   ioc=True,
                   tags=['src:Velociraptor', client_id ],
                   message=description
              )
            
              response = api.create_case_observable(case_id, file_observable)
              if response.status_code != 201:
                self.error({'message': str(response.status_code) + " " + response.text})
              os.remove(filepath)
          except:
            pass
  def operations(self, raw):
      global client_id
      return [self.build_operation('AddTagToArtifact', tag=client_id)]
      return [self.build_operation('AddTagToCase', tag=client_id)]

if __name__ == '__main__':
  Velociraptor().run()
