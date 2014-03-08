Openstack Swift middleware to support Amazon Simple Storage Service API
=======================================================================

SwiftS3 middleware emulates AWS S3 REST api on top of Swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket (Delete bucket; abort running MPUs)
    * GET Bucket (List Objects; List in-progress multipart uploads)
    * PUT Bucket
    * DELETE Object
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swifts3 middleware
before the auth middleware and before any other middleware that
waits for swift requests (like rate limiting).
Example can be found in etc/proxy-server.conf-sample

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password. The host should also point
to the swift storage hostname and it should use the old style
calling format, not the hostname based container format.

An example client using the python boto library might look like the
following for a SAIO setup:

    connection = boto.s3.Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())

Please check the Wiki section for more information.
