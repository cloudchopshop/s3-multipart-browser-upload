from flask import Flask, render_template, request, redirect, Response, jsonify, abort, url_for, make_response
from flask_bootstrap import Bootstrap
from jinja2 import Environment, FileSystemLoader
import boto3
from botocore.client import Config
from config import S3_BUCKET, S3_KEY, S3_SECRET, PREFIX, Azure_ClientAppId, UserPoolId
import os, sys
import requests
import random
import string
from jose import jwt
import json
import base64
import logging

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

application = app = Flask(__name__, static_folder='static')
Bootstrap(app)

#boto s3 client 
def client():
    try:
        client = boto3.client('s3', region_name='us-east-1', config=Config(signature_version='s3v4'), 
        aws_access_key_id=S3_KEY, aws_secret_access_key=S3_SECRET) 
        return client
    except:
        logging.error("Could connect boto client: %s" % str(sys.exc_info()))

#Generate a strong password for the cognito user
def gen_pass():
    try:      
        def get_upper(count=2):
            return ''.join(random.choice(string.ascii_uppercase) for i in range(count))
        def get_lower(count=2):
            return ''.join(random.choice(string.ascii_lowercase) for i in range(count))
        def get_digit(count=2):
            return ''.join(random.choice(string.digits) for i in range(count))
        def get_punct(count=2):
            return ''.join(random.choice(string.punctuation) for i in range(count))
        password_characters = get_upper() + get_lower() + get_digit() + get_punct()
        l = list(password_characters)
        random.shuffle(l)
        return ''.join(l)
    except:
        logging.error("Could connect boto client: %s" % str(sys.exc_info()))


def get_username():
    try:
        decoded_token = get_verified_claims()
        username = decoded_token.get('username')
        if username is None:
            s3_cookie = request.cookies.get('s3_upload_folder')
            logging.debug(f"Using cookie for upload path: '{s3_cookie}'")
            return s3_cookie
        else: 
            logging.debug(f"Using customer username: '{username}'")
            return username
    except:
        logging.error("No customer username or cookie found, running loccally? - using default path")
        return 'default'

def get_verified_claims():
    encoded_jwt = request.headers['x-amzn-oidc-data']
    print('encoded_jwt:', encoded_jwt)
    jwt_headers = encoded_jwt.split('.')[0]
    decoded_jwt_headers = base64.b64decode(jwt_headers)
    decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
    decoded_json = json.loads(decoded_jwt_headers)
    print('decoded_json', decoded_json)
    kid = decoded_json['kid']
    print(kid)
    alg = decoded_json['alg']
    print(alg)
    
    url = 'https://public-keys.auth.elb.us-east-1.amazonaws.com/' + kid
    req = requests.get(url)
    pub_key = req.text
    print('Debug: get_verified_claims: pub_key:', pub_key)
    
    return jwt.decode(encoded_jwt, pub_key, algorithms=[alg])

'''
@app.route('/headers')
def headers():
    #headers = request.headers
    token = request.headers['x-amzn-oidc-data']
    token_claims = jwt.get_unverified_claims(token)
    return "Request headers:\n" + str(token_claims)

@app.route('/verified')
def verified():
    claims = get_verified_claims()
    username = claims.get('username')
    return (username), 200
    #token = request.headers['x-amzn-oidc-data']
    #token_claims = jwt.get_unverified_claims(token)
    #return (token_claims.get("username"))

'''

# Customer Upload Portal Endpoint Site Root
@app.route('/')
@app.route('/admin/files/upload')
def index():
    #print('Debug: Index: get_verified_claims:', get_verified_claims())
    logging.debug("loading index page")
    return render_template("page.html")


# s3 multipart upload api 
@app.route('/s3/api/v1.0', methods=['POST'])
def start():
    command = request.form.get('command')
    # Start the multipart upload process, retrieve an upload id used for the entire process
    if command == 'create':
        try:
            logging.debug(f"/s3/api/v1.0 '{command}' called")
            #print('Debug: Create API: get_username', get_username())
            filename = request.form.get('fileInfo[name]', '')
            key = (PREFIX + get_username() + '/' + str(filename)) #extracted username used to generate upload path ex: 'uploads/john/file.txt'
            #key = (PREFIX + str(filename))
            #print('Debug: Create API: key:', key)
            res = client().create_multipart_upload(Bucket=S3_BUCKET, Key=key)
            upload_id = res['UploadId']
            #print('Debug: Create API: upload_id:', upload_id)
            logging.debug(f"API upload_id: '{upload_id}'")
            return jsonify({'uploadid': upload_id, 'key': key}), 200    
        except:
            logging.error("could not initiate multipart upload: %s" % str(sys.exc_info()))

        
    # Generate and return presigned urls for each upload part
    elif command == 'part':
        try: 
            logging.debug(f"/s3/api/v1.0 '{command}' called")
            key = request.form.get('sendBackData[key]', '')
            upload_id = request.form.get('sendBackData[uploadid]', '')
            part_num = request.form.get('partNumber', '')
            content_len = request.form.get('contentLength', '')
            #print('Debug: Part API: upload_id', upload_id)
            res = client().generate_presigned_url(ClientMethod='upload_part', Params={'Bucket': S3_BUCKET, 'Key': key, 'UploadId': upload_id, 'PartNumber': int(part_num), 'ContentLength': int(content_len)}, ExpiresIn=86400)
            #print('Debug: Part API: url', res)
            logging.debug(f"API upload part url: '{res}'")
            return jsonify({'url': res})
        except:
            logging.error("could not return part url: %s" % str(sys.exc_info()))

    # complete the upload proces, submit all the ETag, Part number json data
    elif command == 'complete':
        try:          
            logging.debug(f"/s3/api/v1.0 '{command}' called")
            key = request.form.get('sendBackData[key]', '')
            upload_id = request.form.get('sendBackData[uploadid]', '')
            # try to get the client upload parts  
            index = 0
            while index < 5:
                try:
                    parts = client().list_parts(Bucket=S3_BUCKET, Key=key, UploadId=upload_id)["Parts"]       
                    print('Debug: parts', parts)
                    break
                except: 
                    index += 1
                    print ("Could not list_parts: %s" % str(sys.exc_info()))
            n_parts = [{k: v for k, v in d.items() if k != 'LastModified' and k != 'Size'} for d in parts]
            logging.debug(f"API upload list parts: '{n_parts}'")    
            #print('Debug: Complete API: n_parts:', n_parts)
            res = client().complete_multipart_upload(Bucket=S3_BUCKET, Key=key, MultipartUpload={'Parts': n_parts}, UploadId=upload_id)
            return jsonify({'success': True})
        except:
            logging.error("could not complete multipart: %s" % str(sys.exc_info()))

    # Cancel the upload process if 'Cancel' recieved from client
    elif command == 'abort':
        try:
            logging.debug(f"/s3/api/v1.0 '{command}' called")
            key = request.form.get('sendBackData[key]', '')
            upload_id = request.form.get('sendBackData[uploadid]', '')
            #print(command)
            res = client().abort_multipart_upload(Bucket=S3_BUCKET, Key=key, UploadId=upload_id)
            return jsonify({'success': True})
        except:
            logging.error("could not abort multipart: %s" % str(sys.exc_info()))

    else:
        abort(400)
        
# Root admin directory, loads 'gen_cust_diretory' form 
@app.route('/admin')
def new_cust_directory_form():
    logging.debug("Loading /admin page")
    return render_template('gen_cust_directory.html')
    
# Post action from admin page, generates a new customer in the cognito user pool     
@app.route('/admin/gen_directory', methods=['POST'])
def gen_cust_directory():
    
    try:
        logging.debug("Loading /admin page")
        directory = request.form["directory"]
        portal = (directory.lower())
        #print('Debug: portal', portal)
        #print(UserPoolId)
        logging.debug(f"upload directory will be: /'{portal}'")
        password = gen_pass()

        aws_client = boto3.client('cognito-idp', region_name='us-east-1', aws_access_key_id=S3_KEY,
            aws_secret_access_key=S3_SECRET)

        res = aws_client.admin_create_user(
            UserPoolId = UserPoolId,
            Username = portal, 
            TemporaryPassword=password
        )
            #UserAttributes = [
            #    {"Name": "first_name", "Value": first_name},
            #    {"Name": "last_name", "Value": last_name},
            #    {"Name": "email_verified", "Value": "true" }
            #]
        #DesiredDeliveryMediums = ['EMAIL']
        logging.debug(f"Cognito User Generate: /'{res}'")
        return render_template('done.html',
                            password=password,
                            url_root=request.url_root,
                            portal=portal)

    except:
        logging.error("Could not create cognito user: %s" % str(sys.exc_info()))
        return ("Error: Failed to Generate User - User May Already Exist")

# Admin view for customer files, path generated from customer directory generation ex: /admin/files?folder=customer1
@app.route('/admin/files')
def files():
    folder = request.args['folder']
    directory = (PREFIX + folder)
    summaries = client().list_objects_v2(Bucket=S3_BUCKET, Prefix=directory)['Contents']
    print('Debug: summaries', summaries)
    res = make_response(render_template('files.html', PREFIX=PREFIX, files=summaries, folder=folder))
    res.set_cookie('s3_upload_folder', folder)
    return res


# Post action from admin files view, download a file from customer directory
@app.route('/admin/files/download', methods=['POST'])
def download():
    key = request.form['key']
    url = client().generate_presigned_url(
    ClientMethod='get_object',
    Params={'Bucket': S3_BUCKET, 'Key': key}, ExpiresIn=86400 #set the url to expire in 1 day for big downloads
    )
    return redirect(url)

# Post action from admin files view, generate an s3 download url to share with customers
@app.route('/admin/files/download_url', methods=['POST'])
def url_download():
    key = request.form['key']
    url = client().generate_presigned_url(
    ClientMethod='get_object',
    Params={'Bucket': S3_BUCKET, 'Key': key}, ExpiresIn=604800 #set the url to expire in 7 days
    )
    return url


if __name__ == "__main__":
    application.run(host='0.0.0.0')