# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The swifts3 middleware will emulate the S3 REST api on top of swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects, List multipart uploads in progress)
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
to the swift storage hostname. It should also use the old style
calling format, not the hostname based container format.

Note that all the operations with multipart upload buckets are denied
to user, as well as multipart buckets are not listed in all buckets list.
In case of GET/DELETE - NoSuchBucket error is returned;
In case of PUT/POST - InvalidBucketName error is returned.

An example client using the python boto library might look like the
following for an SAIO setup::

    connection = boto.s3.Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import unquote, quote
import rfc822
import hmac
import base64
import uuid
import errno
from xml.sax.saxutils import escape as xml_escape
import urlparse

from webob import Request as WebObRequest, Response
from webob.exc import HTTPNotFound
from webob.multidict import MultiDict

import simplejson as json

from swift.common.utils import split_path, get_logger


#XXX: In webob-1.9b copied environment contained link to the original
#     instance of a TrackableMultiDict which reflects to original
#     request.
class Request(WebObRequest):
    def _remove_query_vars(self):
        if 'webob._parsed_query_vars' in self.environ:
            del self.environ['webob._parsed_query_vars']

    def copy(self):
        req = super(Request, self).copy()
        req._remove_query_vars()
        return req

    def copy_get(self):
        req = super(Request, self).copy_get()
        req._remove_query_vars()
        return req

MAX_BUCKET_LISTING = 1000
MAX_UPLOADS_LISTING = 1000
MULTIPART_UPLOAD_PREFIX = 'MPU.'

# List of Query String Arguments of Interest
qsa_of_interest = ['acl', 'defaultObjectAcl', 'location', 'logging',
                   'partNumber', 'policy', 'requestPayment', 'torrent',
                   'versioning', 'versionId', 'versions', 'website',
                   'uploads', 'uploadId', 'response-content-type',
                   'response-content-language', 'response-expires',
                   'response-cache-control', 'response-content-disposition',
                   'response-content-encoding', 'delete', 'lifecycle']


def get_err_response(code):
    """
    Creates a properly formatted xml error response by a
    given HTTP response code,

    :param code: error code
    :returns: webob.response object
    """
    error_table = {
        'AccessDenied':
            (403, 'Access denied'),
        'BucketAlreadyExists':
            (409, 'The requested bucket name is not available'),
        'BucketNotEmpty':
            (409, 'The bucket you tried to delete is not empty'),
        'InvalidArgument':
            (400, 'Invalid Argument'),
        'InvalidBucketName':
            (400, 'The specified bucket is not valid'),
        'InvalidURI':
            (400, 'Could not parse the specified URI'),
        'NoSuchBucket':
            (404, 'The specified bucket does not exist'),
        'SignatureDoesNotMatch':
            (403, 'The calculated request signature does not match '\
            'your provided one'),
        'NoSuchKey':
            (404, 'The resource you requested does not exist'),
        'NoSuchUpload':
            (404, 'The specified multipart upload does not exist.'),
        }

    resp = Response(content_type='text/xml')
    resp.status = error_table[code][0]
    resp.body = error_table[code][1]
    resp.body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
                '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
                 % (code, error_table[code][1])
    return resp


def get_acl(account_name):
    body = ('<AccessControlPolicy>'
            '<Owner>'
            '<ID>%s</ID>'
            '</Owner>'
            '<AccessControlList>'
            '<Grant>'
            '<Grantee xmlns:xsi="http://www.w3.org/2001/'\
            'XMLSchema-instance" xsi:type="CanonicalUser">'
            '<ID>%s</ID>'
            '</Grantee>'
            '<Permission>FULL_CONTROL</Permission>'
            '</Grant>'
            '</AccessControlList>'
            '</AccessControlPolicy>' %
            (account_name, account_name))
    return Response(body=body, content_type="text/plain")


def canonical_string(req):
    """
    Canonicalize a request to a token that can be signed.
    """
    def unquote_v(nv):
        if len(nv) == 1:
            return nv
        else:
            return (nv[0], unquote(nv[1]))

    amz_headers = {}

    buf = "%s\n%s\n%s\n" % (req.method, req.headers.get('Content-MD5', ''),
                            req.headers.get('Content-Type') or '')

    for amz_header in sorted((key.lower() for key in req.headers
                              if key.lower().startswith('x-amz-'))):
        amz_headers[amz_header] = req.headers[amz_header]

    if 'x-amz-date' in amz_headers:
        buf += "\n"
    elif 'Date' in req.headers:
        buf += "%s\n" % req.headers['Date']

    for k in sorted(key.lower() for key in amz_headers):
        buf += "%s:%s\n" % (k, amz_headers[k])

    # don't include anything after the first ? in the resource...
    # unless it is one of the QSA of interest, defined above
    parts = req.path_qs.split('?')
    buf += parts[0]

    if len(parts) > 1:
        qsa = parts[1].split('&')
        qsa = [a.split('=', 1) for a in qsa]
        qsa = [unquote_v(a) for a in qsa if a[0] in qsa_of_interest]
        if len(qsa) > 0:
            qsa.sort(cmp=lambda x, y: cmp(x[0], y[0]))
            qsa = ['='.join(a) for a in qsa]
            buf += '?'
            buf += '&'.join(qsa)
    return buf


def check_container_name_no_such_bucket_error(container_name):
    """Checks that user do not tries to operate with MPU container"""
    if container_name.startswith(MULTIPART_UPLOAD_PREFIX):
        return get_err_response('NoSuchBucket')


def check_container_name_invalid_bucket_name_error(container_name):
    """Checks that user do not tries to operate with MPU container"""
    if container_name.startswith(MULTIPART_UPLOAD_PREFIX):
        return get_err_response('InvalidBucketName')


class ServiceController(object):
    """
    Handles account level requests.
    """
    def __init__(self, env, app, account_name, token, **kwargs):
        self.app = app
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s' % account_name

    def GET(self, req):
        """
        Handle GET Service request
        """
        req.GET.clear()
        req.GET['format'] = 'json'
        resp = req.get_response(self.app)

        status = resp.status_int
        body = resp.body

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            else:
                return get_err_response('InvalidURI')

        containers = json.loads(body)
        # we don't keep the creation time of a bucket (s3cmd doesn't
        # work without that) so we use some bogus
        body = '<?xml version="1.0" encoding="UTF-8"?>' \
            '<ListAllMyBucketsResult ' \
            'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
            '<Buckets>%s</Buckets>' \
            '</ListAllMyBucketsResult>' \
            % ("".join(['<Bucket><Name>%s</Name><CreationDate>' \
                         '2009-02-03T16:45:09.000Z</CreationDate></Bucket>' %
                         xml_escape(i['name']) for i in containers if \
                         not i['name'].startswith(MULTIPART_UPLOAD_PREFIX)]))
                         # we shold not show multipart buckets here

        return Response(status=200, content_type='application/xml', body=body)


class BucketController(object):
    """
    Handles bucket requests.
    """
    def __init__(self, env, app, account_name, token, container_name,
                    **kwargs):
        self.app = app
        self.container_name = unquote(container_name)
        self.account_name = unquote(account_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s/%s' % (account_name, container_name)

    def get_uploads(self, req):
        """Handles listing of in-progress multipart uploads"""
        acl = req.GET.get('acl')
        params = MultiDict([('format', 'json')])
        max_uploads = req.GET.get('max-uploads')
        if (max_uploads is not None and max_uploads.isdigit()):
            max_uploads = min(int(max_uploads), MAX_UPLOADS_LISTING)
        else:
            max_uploads = MAX_UPLOADS_LISTING
        params['limit'] = str(max_uploads + 1)
        for param_name in ('key-marker', 'prefix', 'delimiter',
                                                       'upload-id-marker'):
            if param_name in req.GET:
                params[param_name] = req.GET[param_name]

        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        req.upath_info = cont_path
        req.GET.clear()
        req.GET.update(params)

        resp = req.get_response(self.app)
        status = resp.status_int

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        if acl is not None:
            return get_acl(self.account_name)

        objects = json.loads(resp.body)
        uploads = ''
        splited_name = ''

        for obj in objects:
            if obj['name'].endswith('/meta'):
                splited_name = obj['name'].split('/')
                uploads = uploads.join(
                                 "<Upload>"
                                 "<Key>%s</Key>"
                                 "<UploadId>%s</UploadId>"
                                 "<Initiator>"
                                 "<ID>%s</ID>"
                                 "<DisplayName>%s</DisplayName>"
                                 "</Initiator>"
                                 "<Owner>"
                                 "<ID>%s</ID>"
                                 "<DisplayName>%s</DisplayName>"
                                 "</Owner>"
                                 "<StorageClass>STANDARD</StorageClass>"
                                 "<Initiated>%sZ</Initiated>"
                                 "</Upload>" % (
                                 splited_name[0],
                                 splited_name[1],
                                 self.account_name,
                                 self.account_name,
                                 self.account_name,
                                 self.account_name,
                                 obj['last_modified'][:-3]))
            else:
                objects.remove(obj)

        #TODO: Currently there are less then max_uploads results
        # in a response; Amount of uploads == amount of meta files
        # received in a request for a list of objects in a bucket.

        if len(objects) == (max_uploads + 1):
            is_truncated = 'true'
            next_key_marker = splited_name[0]
            next_uploadId_marker = splited_name[1]
        else:
            is_truncated = 'false'
            next_key_marker = next_uploadId_marker = ''

        body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListMultipartUploadsResult '
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            '<Bucket>%s</Bucket>'
            '<KeyMarker>%s</KeyMarker>'
            '<UploadIdMarker>%s</UploadIdMarker>'
            '<NextKeyMarker>%s</NextKeyMarker>'
            '<NextUploadIdMarker>%s</NextUploadIdMarker>'
            '<MaxUploads>%s</MaxUploads>'
            '<IsTruncated>%s</IsTruncated>'
            '%s'
            '</ListMultipartUploadsResult>' %
                (
                    xml_escape(self.container_name),
                    xml_escape(params.get('key-marker', '')),
                    xml_escape(params.get('upload-id-marker', '')),
                    next_key_marker,
                    next_uploadId_marker,
                    max_uploads,
                    is_truncated,
                    uploads
                )
            )
        return Response(body=body, content_type='application/xml')

    def GET(self, req):
        """
        Handles listing of in-progress multipart uploads,
        handles list objects request.
        """
        # any operations with multipart buckets are not allowed to user
        check_container_name_no_such_bucket_error(self.container_name)

        if 'uploads' in req.GET:
            return self.get_uploads(req)
        else:
            acl = req.GET.get('acl')
            params = MultiDict([('format', 'json')])
            max_keys = req.GET.get('max-keys')
            if (max_keys is not None and max_keys.isdigit()):
                max_keys = min(int(max_keys), MAX_BUCKET_LISTING)
            else:
                max_keys = MAX_BUCKET_LISTING
            params['limit'] = str(max_keys + 1)
            for param_name in ('marker', 'prefix', 'delimiter'):
                if param_name in req.GET:
                    params[param_name] = req.GET[param_name]

            req.GET.clear()
            req.GET.update(params)

            resp = req.get_response(self.app)
            status = resp.status_int
            body = resp.body

            if status != 200:
                if status == 401:
                    return get_err_response('AccessDenied')
                elif status == 404:
                    return get_err_response('InvalidBucketName')
                else:
                    return get_err_response('InvalidURI')

            if acl is not None:
                return get_acl(self.account_name)

            objects = json.loads(resp.body)
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<ListBucketResult '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                '<Prefix>%s</Prefix>'
                '<Marker>%s</Marker>'
                '<Delimiter>%s</Delimiter>'
                '<IsTruncated>%s</IsTruncated>'
                '<MaxKeys>%s</MaxKeys>'
                '<Name>%s</Name>'
                '%s'
                '%s'
                '</ListBucketResult>' %
                (
                    xml_escape(params.get('prefix', '')),
                    xml_escape(params.get('marker', '')),
                    xml_escape(params.get('delimiter', '')),
                    'true' if len(objects) == (max_keys + 1) else 'false',
                    max_keys,
                    xml_escape(self.container_name),
                    "".join(['<Contents><Key>%s</Key><LastModified>%sZ</Last'\
                             'Modified><ETag>%s</ETag><Size>%s</Size><Storage'\
                             'Class>STANDARD</StorageClass></Contents>' %
                             (xml_escape(i['name']), i['last_modified'][:-3],
                                                         i['hash'], i['bytes'])
                            for i in objects[:max_keys] if 'subdir' not in i]),
                    "".join(['<CommonPrefixes><Prefix>%s</Prefix></Common'\
                             'Prefixes>' % xml_escape(i['subdir'])
                             for i in objects[:max_keys] if 'subdir' in i])))

            return Response(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handles PUT Bucket request.
        """
        # any operations with multipart buckets are not allowed to user
        check_container_name_invalid_bucket_name_error(self.container_name)

        resp = req.get_response(self.app)
        status = resp.status_int

        if status != 201:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 202:
                return get_err_response('BucketAlreadyExists')
            else:
                return get_err_response('InvalidURI')

        resp = Response()
        resp.headers.add('Location', self.container_name)
        resp.status = 200
        return resp

    def mpu_bucket_deletion(self, req):
        """
        This method checks if MPU bucket exists and
        if there are any active MPUs are in it.
        MPUs are aborted, parts are deleted.
        """
        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        list_req = req.copy()
        list_req.method = 'GET'
        list_req.upath_info = cont_path
        list_req.GET.clear()
        list_req.GET['format'] = 'json'

        list_resp = list_req.get_response(self.app)
        status = list_resp.status_int

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                # there is no MPU bucket, it's OK, there is only regular bucket
                pass
            else:
                return get_err_response('InvalidURI')

        elif status == 200:
            # aborting multipart uploads by deleting meta and other files
            objects = json.loads(list_resp.body)
            for obj in objects:
                if obj['name'].endswith('/meta'):
                    for mpu_obj in objects:
                        if mpu_obj['name'].startswith(obj['name'][:-5]):
                            obj_req = req.copy()
                            obj_req.upath_info = "%s%s" % (cont_path,
                                                           mpu_obj['name'])
                            obj_req.GET.clear()

                            obj_resp = obj_req.get_response(self.app)
                            status = obj_resp.status_int

                            #TODO: Add some logs here

                            if status not in (200, 204):
                                if status == 401:
                                    return get_err_response('AccessDenied')
                                elif status == 404:
                                    return get_err_response('NoSuchKey')
                                else:
                                    return get_err_response('InvalidURI')

            # deleting multipart bucket
            del_mpu_req = req.copy()
            del_mpu_req.upath_info = cont_path
            del_mpu_req.GET.clear()
            del_mpu_resp = del_mpu_req.get_response(self.app)
            status = del_mpu_resp.status_int

            if status != 204:
                if status == 401:
                    return get_err_response('AccessDenied')
                elif status == 404:
                    return get_err_response('InvalidBucketName')
                elif status == 409:
                    return get_err_response('BucketNotEmpty')
                else:
                    return get_err_response('InvalidURI')

        return Response(status=204)

    def DELETE(self, req):
        """
        Handles DELETE Bucket request.
        Also deletes multipart bucket if it exists.
        Aborts all multipart uploads initiated for this bucket.
        """
        # any operations with multipart buckets are not allowed to user
        check_container_name_no_such_bucket_error(self.container_name)

        # deleting regular bucket,
        # request is copied to save valid authorization
        del_req = req.copy()
        resp = del_req.get_response(self.app)
        status = resp.status_int

        if status != 204:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            elif status == 409:
                return get_err_response('BucketNotEmpty')
            else:
                return get_err_response('InvalidURI')

        # check if there is a multipart bucket and
        # return 204 when everything is deleted
        return self.mpu_bucket_deletion(req)


class NormalObjectController(object):
    """
    Handles requests on objects.
    """

    def __init__(self, env, app, account_name, token, container_name,
                    object_name, **kwargs):
        self.app = app
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s/%s/%s' % (account_name, container_name,
                                             object_name)

    def GETorHEAD(self, req):
        resp = req.get_response(self.app)
        status = resp.status_int
        headers = resp.headers
        app_iter = resp.app_iter

        if 200 <= status < 300:
            if 'acl' in req.GET:
                return get_acl(self.account_name)

            new_hdrs = {}
            for key, val in headers.iteritems():
                _key = key.lower()
                if _key.startswith('x-object-meta-'):
                    new_hdrs['x-amz-meta-' + key[14:]] = val
                elif _key in ('content-length', 'content-type',
                             'content-encoding', 'etag', 'last-modified'):
                    new_hdrs[key] = val
            return Response(status=status, headers=new_hdrs, app_iter=app_iter)
        elif status == 401:
            return get_err_response('AccessDenied')
        elif status == 404:
            return get_err_response('NoSuchKey')
        else:
            return get_err_response('InvalidURI')

    def HEAD(self, req):
        """
        Handles HEAD Object request.
        """
        return self.GETorHEAD(req)

    def GET(self, req):
        """
        Handles GET Object request.
        """
        return self.GETorHEAD(req)

    def PUT(self, req):
        """
        Handles PUT Object and PUT Object (Copy) request.
        """
        environ = req.environ
        for key, value in environ.items():
            if key.startswith('HTTP_X_AMZ_META_'):
                del environ[key]
                environ['HTTP_X_OBJECT_META_' + key[16:]] = value
            elif key == 'HTTP_CONTENT_MD5':
                environ['HTTP_ETAG'] = value.decode('base64').encode('hex')
            elif key == 'HTTP_X_AMZ_COPY_SOURCE':
                environ['HTTP_X_COPY_FROM'] = value

        resp = req.get_response(self.app)
        status = resp.status_int
        headers = resp.headers

        if status != 201:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        if 'HTTP_X_COPY_FROM' in environ:
            body = '<CopyObjectResult>' \
                   '<ETag>"%s"</ETag>' \
                   '</CopyObjectResult>' % headers['ETag']
            return Response(status=200, body=body)
        return Response(status=200, etag=headers['ETag'])

    def DELETE(self, req):
        """
        Handles DELETE Object request.
        """
        resp = req.get_response(self.app)
        status = resp.status_int

        if status not in (200, 204):
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('NoSuchKey')
            else:
                return get_err_response('InvalidURI')
        return Response(status=204)


class MultiPartObjectController(object):
    def __init__(self, env, app, account_name, token, container_name,
                    object_name, **kwargs):
        self.app = app
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)
        self.orig_path_info = env['PATH_INFO']
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s/%s/%s' % (account_name, container_name,
                                             object_name)

    def GET(self, req):
        """
        Lists multipart uploads by uploadId.
        """
        # any operations with multipart buckets are not allowed to user
        check_container_name_no_such_bucket_error(self.container_name)

        upload_id = req.GET.get('uploadId')
        max_parts = req.GET.get('max-parts', '1000')
        part_number_marker = req.GET.get('part-number-marker', '')

        try:
            int(upload_id, 16)
            max_parts = int(max_parts)
            if part_number_marker:
                part_number_marker = int(part_number_marker)
        except (TypeError, ValueError):
            return get_err_response('InvalidURI')

        object_name_prefix_len = len(self.object_name) + 1

        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        meta_path = "%s%s/%s/meta" % (cont_path,
                                      self.object_name,
                                      upload_id)

        meta_req = req.copy()
        meta_req.method = 'HEAD'
        meta_req.body = ''
        meta_req.upath_info = meta_path
        meta_req.GET.clear()

        meta_resp = meta_req.get_response(self.app)
        status = meta_resp.status_int

        if status != 200:
            return get_err_response('NoSuchUpload')

        list_req = req.copy()
        list_req.upath_info = cont_path
        list_req.GET.clear()
        list_req.GET['format'] = 'json'
        list_req.GET['prefix'] = "%s/%s/%s/part/" % (cont_name,
                                                     self.object_name,
                                                     upload_id)
        list_req.GET['limit'] = str(max_parts + 1)
        if part_number_marker:
            list_req.GET['marker'] = "%s/%s/part/%s" % (self.object_name,
                                                        upload_id,
                                                        part_number_marker)

        resp = list_req.get_response(self.app)
        status = resp.status_int

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        objects = json.loads(resp.body)

        if len(objects) > max_parts:
            objects = objects.pop(-1)
            next_marker = objects[-1]['name'][object_name_prefix_len:]
            is_truncated = 'true'
        else:
            next_marker = ''
            is_truncated = 'false'

        if next_marker:
            next_marker = "<NextPartNumberMarker>%</NextPartNumberMarker>" % \
                                                                    next_marker

        if part_number_marker:
            part_number_marker = "<PartNumberMarker>%</PartNumberMarker>" % \
                                                             part_number_marker

        parts = ''.join(("<Part>"
                         "<PartNumber>%s</PartNumber>"
                         "<LastModified>%sZ</LastModified>"
                         "<ETag>\"%s\"</ETag>"
                         "<Size>%s</Size>"
                         "</Part>" % (
                         obj['name'][object_name_prefix_len:],
                         obj['last_modified'][:-3],
                         obj['hash'],
                         obj['bytes']) for obj in objects))

        body = (
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
          "<Bucket>%s</Bucket>"
          "<Key>%s</Key>"
          "<UploadId>%s</UploadId>"
          "<Initiator>"
          "<ID>%s</ID>"
          "<DisplayName>%s</DisplayName>"
          "</Initiator>"
          "<Owner>"
          "<ID>%s</ID>"
          "<DisplayName>%s</DisplayName>"
          "</Owner>"
          "<StorageClass>STANDARD</StorageClass>"
          "%s%s"
          "<MaxParts>%s</MaxParts>"
          "<IsTruncated>%s</IsTruncated>"
          "%s"
          "</ListPartsResult>" % (
          self.container_name,
          self.object_name,
          upload_id,
          self.account_name,
          self.account_name,
          self.account_name,
          self.account_name,
          part_number_marker,
          next_marker,
          max_parts,
          is_truncated,
          parts,
          ))
        return Response(status=200,
                        body=body,
                        content_type='application/xml')

    def post_uploads(self, req):
        """
        Called if POST with 'uploads' query string was received.
        Creates metafile which is used as a flag on uncompleted MPU.
        Initiates multipart upload.
        """
        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        cont_req = req.copy()
        cont_req.method = 'HEAD'
        cont_req.upath_info = cont_path
        cont_req.GET.clear()

        cont_resp = cont_req.get_response(self.app)
        status = cont_resp.status_int

        if status == 404:
            cont_req = req.copy()
            cont_req.method = 'PUT'
            cont_req.upath_info = cont_path
            cont_req.GET.clear()

            cont_resp = cont_req.get_response(self.app)
            status = cont_resp.status_int

        if status not in (201, 204):
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        upload_id = uuid.uuid4().hex

        meta_req = req.copy()
        meta_req.method = 'PUT'
        meta_req.upath_info = "%s%s/%s/meta" % (cont_path,
                                                self.object_name,
                                                upload_id)
        for header, value in meta_req.headers.items():
            if header.lower().startswith('x-amz-meta-'):
                meta_req.headers['X-Object-Meta-Amz-' + header[11:]] = \
                                                                      value

        meta_resp = meta_req.get_response(self.app)
        status = meta_resp.status_int

        if status != 201:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<InitiateMultipartUploadResult '\
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                '<Bucket>%s</Bucket>'
                '<Key>%s</Key>'
                '<UploadId>%s</UploadId>'
                '</InitiateMultipartUploadResult>' %
                (self.container_name, self.object_name, upload_id))

        return Response(status=200,
                        body=body,
                        content_type='application/xml')

    def post_uploadId(self, req):
        """
        Called if POST with 'uploadId' query string was received.
        Deletes metafile after completion of MPU.
        Completes multipart upload.
        """
        upload_id = req.GET.get('uploadId')

        try:
            int(upload_id, 16)
        except (TypeError, ValueError):
            return get_err_response('InvalidURI')

        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)
        meta_path = "%s%s/%s/meta" % (cont_path,
                                      self.object_name,
                                      upload_id)

        meta_req = req.copy()
        meta_req.method = 'HEAD'
        meta_req.body = ''
        meta_req.upath_info = meta_path
        meta_req.GET.clear()

        meta_resp = meta_req.get_response(self.app)
        status = meta_resp.status_int

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('NoSuchUpload')
            else:
                return get_err_response('InvalidURI')

        # TODO: Validate uploaded parts.

        manifest_path = MULTIPART_UPLOAD_PREFIX + \
                                   "%s/%s/%s/part/" % (self.container_name,
                                                       self.object_name,
                                                       upload_id)

        manifest_req = req.copy()
        manifest_req.method = 'PUT'
        manifest_req.GET.clear()
        manifest_req.headers['X-Object-Manifest'] = manifest_path
        for header, value in meta_resp.headers.iteritems():
            if header.lower().startswith('x-object-meta-amz-'):
                manifest_req.headers['x-amz-meta-' + header[18:]] = value

        manifest_resp = manifest_req.get_response(self.app)
        status = manifest_resp.status_int

        if status == 201:
            finish_req = req.copy()
            finish_req.method = 'DELETE'
            finish_req.upath_info = meta_path
            finish_req.body = ''
            finish_req.GET.clear()

            finish_resp = finish_req.get_response(self.app)
            status = finish_resp.status_int

        if status not in (201, 204):
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<CompleteMultipartUploadResult '\
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                '<Location>%s</Location>'
                '<Bucket>%s</Bucket>'
                '<Key>%s</Key>'
                '<ETag>%s</ETag>'
                '</CompleteMultipartUploadResult>' %
                (self.orig_path_info,
                 self.container_name,
                 self.object_name,
                 manifest_resp.headers['ETag']))

        return Response(status=200,
                        body=body,
                        content_type='application/xml')

    def POST(self, req):
        """
        Initiate and complete multipart upload.
        """
        # any operations with multipart buckets are not allowed to user
        check_container_name_invalid_bucket_name_error(self.container_name)

        if 'uploads' in req.GET:
            return self.post_uploads(req)
        elif 'uploadId' in req.GET:
            return self.post_uploadId(req)

        return get_err_response('InvalidURI')

    def PUT(self, req):
        """
        Upload part of a multipart upload.
        """
        upload_id = req.GET.get('uploadId')
        part_number = req.GET.get('partNumber', '')

        try:
            int(upload_id, 16)
        except (TypeError, ValueError):
            return get_err_response('InvalidURI')

        if not part_number.isdigit():
            return get_err_response('InvalidURI')

        # any operations with multipart buckets are not allowed to user
        check_container_name_invalid_bucket_name_error(self.container_name)

        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        meta_path = "%s%s/%s/meta" % (cont_path, self.object_name, upload_id)

        meta_req = req.copy()
        meta_req.method = 'HEAD'
        meta_req.body = ''
        meta_req.upath_info = meta_path
        meta_req.GET.clear()

        meta_resp = meta_req.get_response(self.app)
        status = meta_resp.status_int

        if status != 200:
            return get_err_response('NoSuchUpload')

        req = req.copy()
        req.upath_info = "%s%s/%s/part/%s" % (cont_path, self.object_name,
                                              upload_id, part_number)
        req.GET.clear()

        resp = req.get_response(self.app)
        status = resp.status_int
        headers = resp.headers

        if status != 201:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        if 'HTTP_X_COPY_FROM' in req.environ:
            body = '<CopyObjectResult>' \
                   '<ETag>"%s"</ETag>' \
                   '</CopyObjectResult>' % resp.headers['ETag']
            return Response(status=200, body=body)
        return Response(status=200, etag=resp.headers['ETag'])

    def DELETE(self, req):
        """
        Aborts multipart upload by uploadId.
        """
        upload_id = req.GET.get('uploadId')

        try:
            int(upload_id, 16)
        except (TypeError, ValueError):
            return get_err_response('InvalidURI')

        # any operations with multipart buckets are not allowed to user
        check_container_name_no_such_bucket_error(self.container_name)

        cont_name = MULTIPART_UPLOAD_PREFIX + self.container_name
        cont_path = "/v1/%s/%s/" % (self.account_name, cont_name)

        prefix = "%s/%s/" % (self.object_name, upload_id)

        list_req = req.copy_get()
        list_req.upath_info = cont_path
        list_req.GET.clear()
        list_req.GET['format'] = 'json'
        list_req.GET['prefix'] = prefix

        list_resp = list_req.get_response(self.app)
        status = list_resp.status_int

        if status != 200:
            if status == 401:
                return get_err_response('AccessDenied')
            elif status == 404:
                return get_err_response('InvalidBucketName')
            else:
                return get_err_response('InvalidURI')

        objects = json.loads(list_resp.body)
        for obj in objects:
            obj_req = req.copy()
            obj_req.method = 'DELETE'
            obj_req.upath_info = "%s%s" % (cont_path, obj['name'])
            obj_req.GET.clear()

            obj_resp = obj_req.get_response(self.app)
            status = obj_resp.status_int

            if status not in (200, 204):
                if status == 401:
                    return get_err_response('AccessDenied')
                elif status == 404:
                    return get_err_response('NoSuchKey')
                else:
                    return get_err_response('InvalidURI')

        return Response(status=204)


class ObjectController(NormalObjectController, MultiPartObjectController):
    """Manages requests on normal and multipart objects"""
    def __init__(self, *args, **kwargs):
        MultiPartObjectController.__init__(self, *args, **kwargs)

    def GET(self, req):
        if 'uploadId' in req.GET:
            return MultiPartObjectController.GET(self, req)
        return NormalObjectController.GET(self, req)

    def PUT(self, req):
        if 'uploadId' in req.GET:
            return MultiPartObjectController.PUT(self, req)
        return NormalObjectController.PUT(self, req)

    def POST(self, req):
        if 'uploadId' in req.GET or 'uploads' in req.GET:
            return MultiPartObjectController.POST(self, req)
        return NormalObjectController.POST(self, req)

    def DELETE(self, req):
        if 'uploadId' in req.GET:
            return MultiPartObjectController.DELETE(self, req)

        obj_req = req.copy_get()
        obj_req.method = 'HEAD'
        obj_req.GET.clear()

        obj_resp = obj_req.get_response(self.app)
        status = obj_resp.status_int

        if status == 200 and 'X-Object-Manifest' in obj_resp.headers:
            manifest = obj_resp.headers['X-Object-Manifest']
            upload_id = manifest.split('/')[2]

            del_req = req.copy()
            del_req.GET['uploadId'] = upload_id

            MultiPartObjectController.DELETE(self, del_req)
        return NormalObjectController.DELETE(self, req)


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app

    def get_controller(self, path, params):
        container, obj = split_path(path, 0, 2, True)
        d = dict(container_name=container, object_name=obj)

        if container and obj:
            return ObjectController, d
        elif container:
            return BucketController, d
        return ServiceController, d

    def __call__(self, env, start_response):
        req = Request(env)

        if 'AWSAccessKeyId' in req.GET:
            try:
                req.headers['Date'] = req.GET['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.GET
            except KeyError:
                return get_err_response('InvalidArgument')(env, start_response)

        if not 'Authorization' in req.headers:
            return self.app(env, start_response)

        try:
            account, signature = \
                req.headers['Authorization'].split(' ')[-1].rsplit(':', 1)
        except Exception:
            return get_err_response('InvalidArgument')(env, start_response)
        try:
            controller, path_parts = self.get_controller(req.path, req.GET)
        except ValueError:
            return get_err_response('InvalidURI')(env, start_response)

        token = base64.urlsafe_b64encode(canonical_string(req))

        controller = controller(req.environ,
                                self.app,
                                account,
                                token,
                                **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            return get_err_response('InvalidURI')(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swifts3_filter(app):
        return Swift3Middleware(app, conf)

    return swifts3_filter
