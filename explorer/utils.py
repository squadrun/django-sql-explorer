import functools
import re

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView
from django.contrib.auth import REDIRECT_FIELD_NAME
from sqlparse import format as sql_format

from explorer import app_settings

EXPLORER_PARAM_TOKEN = "$$"


def passes_blacklist(sql):
    clean = functools.reduce(
        lambda s, term: s.upper().replace(term, ''),
        [t.upper() for t in app_settings.EXPLORER_SQL_WHITELIST],
        sql
    )

    regex_blacklist = [
        (
            bl_word,
            re.compile(
                r'(^|\W){}($|\W)'.format(bl_word),
                flags=re.IGNORECASE
            )
        )
        for bl_word in app_settings.EXPLORER_SQL_BLACKLIST
    ]

    fails = [
        bl_word
        for bl_word, bl_regex in regex_blacklist
        if bl_regex.findall(clean)
    ]

    return not any(fails), fails


def _format_field(field):
    return field.get_attname_column()[1], field.get_internal_type()


def param(name):
    return f"{EXPLORER_PARAM_TOKEN}{name}{EXPLORER_PARAM_TOKEN}"


def swap_params(sql, params):
    p = params.items() if params else {}
    for k, v in p:
        regex = re.compile(r"\$\$%s(?:\:([^\$]+))?\$\$" % str(k).lower(), re.I)
        sql = regex.sub(str(v), sql)
    return sql


def extract_params(text):
    regex = re.compile(r"\$\$([a-z0-9_]+)(?:\:([^\$]+))?\$\$")
    params = re.findall(regex, text.lower())
    return {p[0]: p[1] if len(p) > 1 else '' for p in params}


def safe_login_prompt(request):
    defaults = {
        'template_name': 'admin/login.html',
        'authentication_form': AuthenticationForm,
        'extra_context': {
            'title': 'Log in',
            'app_path': request.get_full_path(),
            REDIRECT_FIELD_NAME: request.get_full_path(),
        },
    }
    return LoginView.as_view(**defaults)(request)


def shared_dict_update(target, source):
    for k_d1 in target:
        if k_d1 in source:
            target[k_d1] = source[k_d1]
    return target


def safe_cast(val, to_type, default=None):
    try:
        return to_type(val)
    except ValueError:
        return default


def get_int_from_request(request, name, default):
    val = request.GET.get(name, default)
    return safe_cast(val, int, default) if val else None


def get_params_from_request(request):
    val = request.GET.get('params', None)
    try:
        d = {}
        tuples = val.split('|')
        for t in tuples:
            res = t.split(':')
            d[res[0]] = res[1]
        return d
    except Exception:
        return None


def get_params_for_url(query):
    if query.params:
        return '|'.join([f'{p}:{v}' for p, v in query.params.items()])


def url_get_rows(request):
    return get_int_from_request(
        request, 'rows', app_settings.EXPLORER_DEFAULT_ROWS
    )


def url_get_query_id(request):
    return get_int_from_request(request, 'query_id', None)


def url_get_log_id(request):
    return get_int_from_request(request, 'querylog_id', None)


def url_get_show(request):
    return bool(get_int_from_request(request, 'show', 1))


def url_get_fullscreen(request):
    return bool(get_int_from_request(request, 'fullscreen', 0))


def url_get_params(request):
    return get_params_from_request(request)


def allowed_query_pks(user_id):
    return app_settings.EXPLORER_GET_USER_QUERY_VIEWS().get(user_id, [])


def user_can_see_query(request, **kwargs):
    if not request.user.is_anonymous and 'query_id' in kwargs:
        return int(kwargs['query_id']) in allowed_query_pks(request.user.id)
    return False


def fmt_sql(sql):
    return sql_format(sql, reindent=True, keyword_case='upper')


def noop_decorator(f):
    return f


class InvalidExplorerConnectionException(Exception):
    pass


def get_valid_connection(alias=None):
    from explorer.connections import connections

    if not alias:
        return connections[app_settings.EXPLORER_DEFAULT_CONNECTION]

    if alias not in connections:
        raise InvalidExplorerConnectionException(
            f'Attempted to access connection {alias}, '
            f'but that is not a registered Explorer connection.'
        )
    return connections[alias]


class Undefined:
    """Placeholder for undefined values (can't use None)"""


def dictattr(dict_, name, default=Undefined()):
    """
    Given a dotted path as name, return the nested value from the dict,
    returning the default if not found, or raising AttributeError if the
    path is not found.

    :param dict_: the dict containing the values
    :type dict_: dict
    :param name: dotted-path of the value to return from the dict
    :type name: str
    :param default: default value to return if the named value is not found,
                    if not specified, we'll return
    :type default: Undefined or value
    :return: the result of following the dotted-path through dict to resolve
             a target value
    :raise AttributeError: if the named value is not found in the dict and no
                           default value is specified.
    """
    components = name.split('.')
    result = dict_
    for component in components:
        if component not in result:
            if isinstance(default, Undefined):
                raise AttributeError()
            return default
        result = result[component]
    return result


def s3_get_client():
    try:
        # Optional dependency
        import boto3

        return boto3.client(
            "s3",
            region_name=app_settings.S3_REGION,
            aws_access_key_id=app_settings.S3_ACCESS_KEY,
            aws_secret_access_key=app_settings.S3_SECRET_KEY
        )
    except ImportError:
        return None


def s3_put_object_from_file(
        bucket,
        key,
        content,
        content_type,
        content_encoding=None,
        content_disposition=None,
        acl=app_settings.S3_ACL,
        cache_control=app_settings.S3_CACHE_CONTROL,
        cb=None,
):
    """
    Put an object onto S3 in the specified bucket under the specified key
    using in-memory content.

    :param bucket: the bucket name
    :type bucket: str
    :param key: the key to store the new object under in the bucket
    :type key: str
    :param content: the content of the new object, as either a file-name or a
                    file-like object
    :type content: str or object
    :param content_type: the MIME type of the content along with any character
                         encoding, e.g. 'text/html; charset=utf-8'
    :type content_type: str
    :param content_encoding: optional content encoding, this should be passed
                             as 'gzip' if uploading gzipped content, else
                             left blank
    :type content_encoding: str or NoneType
    :param content_disposition: optional content presentation, this should be
                                used if the thing being uploaded is to be
                                treated as a file download, e.g. a report...
                                certain browsers need this particular header to
                                be in place in order to correctly download the
                                file with the desired filename. e.g. value:
                                'attachment; filename=some-report.csv'
    :type content_disposition: NoneType or str
    :param acl: the access control level of the new object, by default this is
                set to be 'private'
    :type acl: str
    :param cache_control: cache-control header to apply to the new object,
                          'no-cache' by default
    :type cache_control: str
    :param cb: optional callback function to receive a single integer parameter
               indicating the number of bytes uploaded, periodically called
               as upload occurs.
    :type cb: callable or NoneType
    """
    from botocore.exceptions import ClientError

    if cb and not callable(cb):
        raise ValueError('cb must be a callable!')

    if isinstance(content, str):
        # assume content is a file-name
        content = open(content, 'rb')

    elif hasattr(content, 'read') and callable(getattr(content, 'read')):
        # assume content is a file-like object
        content = open(content.name, 'rb')
    else:
        raise ValueError('content must be a file-path or a file-like object')

    data = content.read()
    content.close()

    def default_cb(bytes_uploaded):
        """
        Default callback if no other callback is specified

        :param bytes_uploaded: the number of bytes of the file uploaded
        :type bytes_uploaded: int
        """
        print('Uploaded {bytes_uploaded} byte(s) of "{key}"'.format(
            bytes_uploaded=bytes_uploaded,
            key=key
        ))

    cb = cb or default_cb

    client = s3_get_client()

    params = {
        'Bucket': bucket,
        'Key': key,
        'Body': data,
        'ContentType': content_type,
        'ACL': acl,
        'CacheControl': cache_control,
    }

    if content_encoding:
        params['ContentEncoding'] = content_encoding

    if content_disposition:
        params['ContentDisposition'] = content_disposition

    try:
        response = client.put_object(**params) or {}
        status_code = dictattr(
            response, 'ResponseMetadata.HTTPStatusCode', None)
        if status_code == 200:
            # note: put_object() does not accept a callback function, best
            # we can do is call it once with 100% progress after the fact
            cb(len(data))

    except ClientError as e:
        raise


def s3_upload(key, data):
    """Should return URL of the file on S3"""
    s3_put_object_from_file(
        bucket=app_settings.S3_BUCKET,
        key=key,
        content=data,
        content_type='text/csv'
    )
    return f'https://{app_settings.S3_BUCKET}.s3.amazonaws.com/{key}'
