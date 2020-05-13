# s3CustomerUploads

This app is used to generate an upload location for large customer files.  (200GB files tested.)


## How it is intended to work

The 'admin' will use the /admin path to generate an 'upload directory'. Once the 'upload directory' is generated an upload url, username (same as upload path), and password will be viewable, this is intended for the customer. There will also be an Admin link to download the file, upload additional files and create file download links designed to share additional files with customers. 

## s3 Bucket / IAM setup

A bucket must first be configured before using this app. 

Recomend using a bucket lifecycle rule to cleanup old files. 

A CORS configuration policy is needed, permitting the user uploads

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <CORSRule>
        <AllowedOrigin>*</AllowedOrigin>
        <AllowedMethod>PUT</AllowedMethod>
        <AllowedMethod>POST</AllowedMethod>
        <AllowedMethod>GET</AllowedMethod>
        <AllowedMethod>HEAD</AllowedMethod>
        <AllowedHeader>*</AllowedHeader>
    </CORSRule>
    </CORSConfiguration> 
    ```

An IAM user with key and secret must be provisioned.  
Create and map a policy that grants the new user access to the new bucket.

Note: The bellow policy grants the IAM account access to the bucket.  
Example: 

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObject",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
                "s3:ListBucketMultipartUploads"
            ],
            "Resource": [
                "arn:aws:s3:::{bucketname}/*",
                "arn:aws:s3:::{bucketname}"
            ]
        }
    ]
}
```

Setup .env file for access keys   
Example:  
export FLASK_APP=app.py  
export FLASK_DEBUG=1  

export S3_BUCKET='your_bucket'  
export S3_KEY='your_key'  
export S3_SECRET_ACCESS_KEY='your_secret'  
export PREFIX='uploads/'  
export Cognito_PoolId='your_poolid'  

## Notes 
This app is provided as is.  
There is no auth bult into this app, designed to sit behind aws app load balancer hosted with beanstalk, secured with path rules. 

