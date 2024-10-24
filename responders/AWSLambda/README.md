### AWS Lambda Responder

This responder triggers an AWS Lambda function using the provided credentials and configuration, directly from TheHive. By default, it can be triggered from an alert, case, observable, task and sends the data of the object as input to the AWS Lambda Function for its execution. 
Make sure to manage these different objects appropriately if needed.

#### Setup example
- Log in to your [AWS Management Console](https://aws.amazon.com/console/) go to **IAM**
- Create a **new IAM user** (e.g. CortexAWSlambda-invoke-responder) with AWS Credentials type : Access key - Programmatic
- Choose **attach policies directly** and attach a policy you created with least privilege, for example:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": [
                "arn:aws:lambda:<AWS_REGION>:<AWS_ACCOUNT_ID>:function:<LAMBDA_FUNCTION_NAME>"
            ]
        }
    ]
}
```
- Go to your newly created user, to **Security tab** and create **access key** for an **Application running outside AWS**
- Configure properly the responder with the right credentials & aws region

#### Successful Execution

When an execution is successful in `RequestResponse` mode, the responder will be marked as "Success" with a report message in the following format:

```
{ "message": "Lambda function '<name-of-lambda-function>' invoked successfully.", "response": "<response from lambda function>" }
```

#### Failed Execution

When an execution fails in `RequestResponse` mode, the responder will be marked as "Failure" with a report message in the following format:
```
"[{error_type}] {message}: {details}\n\nAdditional info: {additional_info}"
```
