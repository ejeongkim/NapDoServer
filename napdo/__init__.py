import datetime
import os
import re
import time
from pprint import pformat
from urllib import urlencode, quote
from urlparse import urljoin, urlparse
from django.core.exceptions import SuspiciousOperation
from django.utils.datastructures import MultiValueDict, ImmutableList
from django.utils.encoding import smart_str, iri_to_uri, force_unicode
from django.utils.http import cookie_date
from django.http.multipartparser import MultiPartParser
from django.conf import settings
from django.core.files import uploadhandler
from utils import *

RESERVED_CHARS="!*'();:@&=+$,/?%#[]"

absolute_http_url_re = re.compile(r"^https?://", re.I)
host_validation_re = re.compile(r"^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9:]+\])(:\d+)?$")


class Http404(Exception):
    pass

class HttpResponse(object):
    """A basic HTTP response, with content and dictionary-accessed headers."""

    status_code = 200

    def __init__(self, content='', mimetype=None, status=None,
            content_type=None):
        # _headers is a mapping of the lower-case name to the original case of
        # the header (required for working with legacy systems) and the header
        # value.  Both the name of the header and its value are ASCII strings.
        self._headers = {}
        self._charset = settings.DEFAULT_CHARSET
        if mimetype:
            content_type = mimetype     # For backwards compatibility
        if not content_type:
            content_type = "%s; charset=%s" % (settings.DEFAULT_CONTENT_TYPE,
                    self._charset)
        if not isinstance(content, basestring) and hasattr(content, '__iter__'):
            self._container = content
            self._is_string = False
        else:
            self._container = [content]
            self._is_string = True
        self.cookies = SimpleCookie()
        if status:
            self.status_code = status

        self['Content-Type'] = content_type

    def __str__(self):
        """Full HTTP message, including headers."""
        return '\n'.join(['%s: %s' % (key, value)
            for key, value in self._headers.values()]) \
            + '\n\n' + self.content

    def _convert_to_ascii(self, *values):
        """Converts all values to ascii strings."""
        for value in values:
            if isinstance(value, unicode):
                try:
                    value = value.encode('us-ascii')
                except UnicodeError:
                    e.reason += 'HTTP response headers must be in US-ASCII format'
                    raise
            else:
                value = str(value)
            if '\n' in value or '\r' in value:
                raise BadHeaderError("Header values can't contain newlines (got %r)" % (value))
            yield value

    def __setitem__(self, header, value):
        header, value = self._convert_to_ascii(header, value)
        self._headers[header.lower()] = (header, value)

    def __delitem__(self, header):
        try:
            del self._headers[header.lower()]
        except KeyError:
            pass

    def __getitem__(self, header):
        return self._headers[header.lower()][1]

    def has_header(self, header):
        """Case-insensitive check for a header."""
        return self._headers.has_key(header.lower())

    __contains__ = has_header

    def items(self):
        return self._headers.values()

    def get(self, header, alternate):
        return self._headers.get(header.lower(), (None, alternate))[1]

    def set_cookie(self, key, value='', max_age=None, expires=None, path='/',
                   domain=None, secure=False, httponly=False):
        """
        Sets a cookie.
        ``expires`` can be a string in the correct format or a
        ``datetime.datetime`` object in UTC. If ``expires`` is a datetime
        object then ``max_age`` will be calculated.
        """
        self.cookies[key] = value
        if expires is not None:
            if isinstance(expires, datetime.datetime):
                delta = expires - expires.utcnow()
                # Add one second so the date matches exactly (a fraction of
                # time gets lost between converting to a timedelta and
                # then the date string).
                delta = delta + datetime.timedelta(seconds=1)
                # Just set max_age - the max_age logic will set expires.
                expires = None
                max_age = max(0, delta.days * 86400 + delta.seconds)
            else:
                self.cookies[key]['expires'] = expires
        if max_age is not None:
            self.cookies[key]['max-age'] = max_age
            # IE requires expires, so set it if hasn't been already.
            if not expires:
                self.cookies[key]['expires'] = cookie_date(time.time() +
                                                           max_age)
        if path is not None:
            self.cookies[key]['path'] = path
        if domain is not None:
            self.cookies[key]['domain'] = domain
        if secure:
            self.cookies[key]['secure'] = True
        if httponly:
            self.cookies[key]['httponly'] = True

    def delete_cookie(self, key, path='/', domain=None):
        self.set_cookie(key, max_age=0, path=path, domain=domain,
                        expires='Thu, 01-Jan-1970 00:00:00 GMT')

    def _get_content(self):
        if self.has_header('Content-Encoding'):
            return ''.join(self._container)
        return smart_str(''.join(self._container), self._charset)

    def _set_content(self, value):
        self._container = [value]
        self._is_string = True

    content = property(_get_content, _set_content)

    def __iter__(self):
        self._iterator = iter(self._container)
        return self

    def next(self):
        chunk = self._iterator.next()
        if isinstance(chunk, unicode):
            chunk = chunk.encode(self._charset)
        return str(chunk)

    def close(self):
        if hasattr(self._container, 'close'):
            self._container.close()

    # The remaining methods partially implement the file-like object interface.
    # See http://docs.python.org/lib/bltin-file-objects.html
    def write(self, content):
        if not self._is_string:
            raise Exception("This %s instance is not writable" % self.__class__)
        self._container.append(content)

    def flush(self):
        pass

    def tell(self):
        if not self._is_string:
            raise Exception("This %s instance cannot tell its position" % self.__class__)
        return sum([len(chunk) for chunk in self._container])

class HttpResponseRedirectBase(HttpResponse):
    allowed_schemes = ['http', 'https', 'ftp']

    def __init__(self, redirect_to):
        super(HttpResponseRedirectBase, self).__init__()
        parsed = urlparse(redirect_to)
        if parsed[0] and parsed[0] not in self.allowed_schemes:
            raise SuspiciousOperation("Unsafe redirect to URL with scheme '%s'" % parsed[0])
        self['Location'] = iri_to_uri(redirect_to)

class HttpResponseRedirect(HttpResponseRedirectBase):
    status_code = 302

class HttpResponsePermanentRedirect(HttpResponseRedirectBase):
    status_code = 301

class HttpResponseNotModified(HttpResponse):
    status_code = 304

class HttpResponseBadRequest(HttpResponse):
    status_code = 400

class HttpResponseNotFound(HttpResponse):
    status_code = 404

class HttpResponseForbidden(HttpResponse):
    status_code = 403

class HttpResponseNotAllowed(HttpResponse):
    status_code = 405

    def __init__(self, permitted_methods):
        super(HttpResponseNotAllowed, self).__init__()
        self['Allow'] = ', '.join(permitted_methods)

class HttpResponseGone(HttpResponse):
    status_code = 410

class HttpResponseServerError(HttpResponse):
    status_code = 500

# A backwards compatible alias for HttpRequest.get_host.
def get_host(request):
    return request.get_host()

# It's neither necessary nor appropriate to use
# django.utils.encoding.smart_unicode for parsing URLs and form inputs. Thus,
# this slightly more restricted function.
def str_to_unicode(s, encoding):
    """
    Converts basestring objects to unicode, using the given encoding. Illegally
    encoded input characters are replaced with Unicode "unknown" codepoint
    (\ufffd).
    Returns any non-basestring objects without change.
    """
    if isinstance(s, str):
        return unicode(s, encoding, 'replace')
    else:
        return s

def validate_host(host, allowed_hosts):
    """
    Validate the given host header value for this site.
    Check that the host looks valid and matches a host or host pattern in the
    given list of ``allowed_hosts``. Any pattern beginning with a period
    matches a domain and all its subdomains (e.g. ``.example.com`` matches
    ``example.com`` and any subdomain), ``*`` matches anything, and anything
    else must match exactly.
    Return ``True`` for a valid host, ``False`` otherwise.
    """
    # All validation is case-insensitive
    host = host.lower()

    # Basic sanity check
    if not host_validation_re.match(host):
        return False

    # Validate only the domain part.
    if host[-1] == ']':
        # It's an IPv6 address without a port.
        domain = host
    else:
        domain = host.rsplit(':', 1)[0]

    for pattern in allowed_hosts:
        pattern = pattern.lower()
        match = (
            pattern == '*' or
            pattern.startswith('.') and (
                domain.endswith(pattern) or domain == pattern[1:]
                ) or
            pattern == domain
            )
        if match:
            return True

    return False