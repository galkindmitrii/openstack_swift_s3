swift-swifts3
=============

The swifts3 middleware will emulate the S3 REST api on top of swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects; List in-progress multipart uploads)
    * PUT Bucket
    * DELETE Object
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swifts3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    connection = boto.s3.Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
