#!/usr/bin/env python3
from cortexutils.responder import Responder
import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError

class InvokeLambda(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.aws_access_key_id = self.get_param('config.aws_access_key_id', None, 'AWS Access Key ID missing')
        self.aws_secret_access_key = self.get_param('config.aws_secret_access_key', None, 'AWS Secret Access Key missing')
        self.aws_region = self.get_param('config.aws_region', None, 'AWS Region missing')
        self.lambda_function_name = self.get_param('config.lambda_function_name', None, 'Lambda Function Name missing')

    def run(self):
        Responder.run(self)

        payload_data = self.get_param("data", None, "No data was passed from TheHive")

        # Initialize a session using Amazon Lambda
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region
        )

        # Initialize the Lambda client
        lambda_client = session.client('lambda')

        try:
            # Invoke the Lambda function
            response = lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',  # or 'Event' for asynchronous invocation
                Payload=json.dumps(payload_data)
            )
            if 'FunctionError' in response:
                self.error({'message': f"Error from Lambda function: {response['FunctionError']}"})
            response_payload = json.loads(response['Payload'].read())
            self.report({'message': 'Lambda function invoked successfully', 'response': response_payload})

        except BotoCoreError as e:
            self.error({'message': f"BotoCoreError: {e}"})

        except ClientError as e:
            error_message = e.response['Error']['Message']
            self.error({'message': f"ClientError: {error_message}"})

        except Exception as e:
            self.error({'message': f"Exception: {e}"})

    def operations(self, raw):
        tag = f"AWSLambdaInvoked-{self.lambda_function_name}"
        return [self.build_operation('AddTagToCase', tag=tag)]

if __name__ == '__main__':
    InvokeLambda().run()
