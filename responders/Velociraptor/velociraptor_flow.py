#!/usr/bin/env python3
from cortexutils.responder import Responder
import json
import grpc
import re
import time
import yaml
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

class Velociraptor(Responder):
  def __init__(self):
    Responder.__init__(self)
    self.configpath = self.get_param('config.velociraptor_client_config', None, "File path missing!")
    self.config = yaml.load(open(self.configpath).read(), Loader=yaml.FullLoader)
    self.artifact = self.get_param('config.velociraptor_artifact', None, 'Artifact missing!')
    self.artifact_args = self.get_param('config.velociraptor_artifact_args', None)
    self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
    self.observable = self.get_param('data.data', None, 'Data missing!')
    self.max_wait = self.get_param('config.query_max_duration', 600)
    self.query = self.get_param('config.velociraptor_query', None)
   
  def run(self):
    Responder.run(self)
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
      
        # Query to get client ID
        client_request = api_pb2.VQLCollectorArgs(
            # Setting static max_wait here, because it should not take as long as other queries
            max_wait=60,
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
       
        # Free-form query
        freeform_query = self.query  
         
        # Artifact query
        artifact_query = "LET collection <= collect_client(client_id='"+ client_id +"',artifacts=['" + self.artifact + "'], spec=dict()) LET collection_completed <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id  LIMIT 1 SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id, artifact=collection_completed.Flow.artifacts_with_results[0])"

        

        request = api_pb2.VQLCollectorArgs(
            max_wait=self.max_wait,
            Query=[api_pb2.VQLRequest(
                Name="TheHive-Query",
                VQL=artifact_query,
            )])

        for response in stub.Query(request):
          try:
            query_results = json.loads(response.Response)
            #flow=list(init_results[0].values())[0]
            self.report({'message': query_results })
          except:
            pass

  def operations(self, raw):
      global client_id
      return [self.build_operation('AddTagToArtifact', tag=client_id)]
      return [self.build_operation('AddTagToCase', tag=client_id)]

if __name__ == '__main__':
  Velociraptor().run()
