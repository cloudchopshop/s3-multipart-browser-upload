import os
#from dotenv import load_dotenv
#project_folder = os.path.expanduser('~/my-project-dir') 
#load_dotenv(os.path.join(project_folder, '.env'))

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_KEY = os.environ.get("S3_KEY")
S3_SECRET = os.environ.get("S3_SECRET_ACCESS_KEY")
Azure_ClientAppId = os.environ.get('Azure_ClientAppId')
PREFIX = os.environ.get('PREFIX')
UserPoolId = os.environ.get('Cognito_PoolId')




