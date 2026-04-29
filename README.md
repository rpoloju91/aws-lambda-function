



node test-local.mjs

#//----------------------------------------------//

Option 2: AWS SAM CLI (The Industry Standard)
If you want to test it exactly as AWS would run it (inside a Docker container), use the AWS Serverless Application Model (SAM).

Install SAM CLI: Official AWS Guide.

Create a template.yaml in your root:

YAML
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  PreTokenFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ./
      Handler: index.handler
      Runtime: nodejs20.x
      Environment:
        Variables:
          ROLE_API_URL: http://host.docker.internal:8080 # Points to your local Spring Boot
          INTERNAL_API_KEY: dev-secret-key-12345
Run the function:

Bash
sam local invoke PreTokenFunction -e event.json
