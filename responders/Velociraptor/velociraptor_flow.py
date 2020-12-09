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
    self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
    self.observable = self.get_param('data.data', None, 'Data missing!')

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
            self.report({'message': init_results })
             
            # Define second query
            flow_query = "SELECT * from flows(client_id='" + str(flow['request']['client_id']) + "', flow_id='" + str(flow['flow_id']) + "')"
         
            state=0

            # Check to see if the flow has completed        
            while (state == 0):
    
              followup_request = api_pb2.VQLCollectorArgs(
                max_wait=1,
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
              if state == 1:
                time.sleep(5)
                break

            # Grab the source from the artifact
            source_query="SELECT * from source(client_id='"+ str(flow['request']['client_id']) + "', flow_id='" + str(flow['flow_id']) +  "', artifact='" + self.artifact + "')"
            source_request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            Query=[api_pb2.VQLRequest(
                Name="TheHive-SourceQuery",
                VQL=source_query,
            )])
            source_results=[]
            for source_response in stub.Query(source_request):
              try:
                source_result = json.loads(source_response.Response)
                source_results += source_result
                self.report({'message': source_results })
              except:
                pass
          except:
            pass

  def operations(self, raw):
      global client_id
      return [self.build_operation('AddTagToArtifact', tag=client_id)]
      return [self.build_operation('AddTagToCase', tag=client_id)]

if __name__ == '__main__':
  Velociraptor().run()
