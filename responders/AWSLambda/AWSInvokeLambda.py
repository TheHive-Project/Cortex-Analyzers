#!/usr/bin/env python3
from cortexutils.responder import Responder
import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError

class AWSLambda(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.aws_access_key_id = self.get_param('config.aws_access_key_id', None, 'AWS Access Key ID missing')
        self.aws_secret_access_key = self.get_param('config.aws_secret_access_key', None, 'AWS Secret Access Key missing')
        self.aws_region = self.get_param('config.aws_region', None, 'AWS Region missing')
        self.lambda_function_name = self.get_param('config.lambda_function_name', None, 'Lambda Function Name missing')
        self.invocation_type = self.get_param('config.invocation_type', None, 'RequestResponse')
        self.add_tag_to_case = self.get_param('config.add_tag_to_case', True)

    def run(self):
        Responder.run(self)

        payload_data = self.get_param("data", None, "No data was passed from TheHive")

        # Initialize a session using boto3
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
                InvocationType=self.invocation_type,
                Payload=json.dumps(payload_data)
            )
            
            
            if self.invocation_type == 'Event':
                # In case of async invocations (Event)  , there is no response payload
                message = f'Lambda function {self.lambda_function_name} invoked asynchronously (Event mode). Invocation acknowledged, no response payload.'
                self.report({"message": message})
                return
            
            if 'FunctionError' in response:
                self._handle_error(
                    message="Error from Lambda function",
                    error_type='LambdaFunctionError',
                    details=response.get('FunctionError', 'Unknown function error'),
                    additional_info=None
                )
                return
            
            # Extract and decode response payload
            response_payload = json.loads(response['Payload'].read())
            message=f'Lambda function {self.lambda_function_name} invoked successfully: {response_payload}'
            self.report({"message": message})

        except BotoCoreError as e:
            self._handle_error(
                message="BotoCoreError occurred",
                error_type='BotoCoreError',
                details=str(e)
            )

        except ClientError as e:
            error_message = e.response['Error']['Message']
            self._handle_error(
                message="ClientError occurred",
                error_type='ClientError',
                details=error_message,
                additional_info=e.response
            )

        except Exception as e:
            self._handle_error(
                message="An unexpected exception occurred",
                error_type='GeneralException',
                details=str(e)
            )

    def _handle_error(self, message, error_type, details, additional_info=None):
        """Helper function to handle errors and return a string message."""
        error_message = f"[{error_type}] {message}: {details} \n\nAdditional info: {additional_info}"
        self.error(error_message)

    def operations(self, raw):
        operations = []
        if self.add_tag_to_case:
            tag = f"AWSLambdaInvoked-{self.lambda_function_name}"
            operations.append(self.build_operation('AddTagToCase', tag=tag))
        return operations

if __name__ == '__main__':
    AWSLambda().run()
