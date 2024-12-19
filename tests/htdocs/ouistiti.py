import sys

class HttpRequest:
    META = {}
    QUERY = {}
    COOKIES = {}
    _body = b""
    method = "GET"
    _read_started = False

    def __init__(self):
        pass

    def _load(self):
        self.content_type = self.META['CONTENT_TYPE']
        if self.META['QUERY_STRING']:
            self.QUERY = self.parse_query(self.META['QUERY_STRING'])

    def parse_query(self, string):
        entries = string.split("&")
        return dict(s.split('=') for s in entries)

    @property
    def scheme(self):
        if self.is_secure():
            return "https"
        return "http"

    def is_secure(self):
        return "HTTPS" in self.META

    @property
    def method(self):
        return self.META["REQUEST_METHOD"]

    def _get_query(self):
        return self.QUERY

    def _set_query(self, query):
        self.QUERY = query
    POST = property(_get_query, _set_query)
    GET = property(_get_query, _set_query)

    def __setitem__(self, key, value):
        if isinstance(value, str):
            value = bytes(value,self._charset)
        self.QUERY[key.lower()] = (key, value)

    def __delitem__(self, key):
        self.QUERY.pop(key.lower(), False)

    def __getitem__(self, key):
        return self.QUERY[key.lower()][1]

    def __iter__(self):
        return iter(self._body)

    @property
    def body(self):
        return self._body

class HttpResponse:
    _container = None
    status_code = None
    _headers = {}
    closed = False

    def __init__(self, content = None, content_type = 'text/plain', status = 200, charset = "utf-8"):
        self._charset = charset
        self._headers = {}
        self.content_type = content_type
        self["Content-Type"] = content_type
        if content and len(content) > 0:
            self.content = content
        else:
            self.status_code = 204
        self.status_code = int(status)

    def close(self):
        self.closed = True

    def __setitem__(self, header, value):
        self._headers[header] = value

    def __delitem__(self, header):
        del self._headers[header]

    def __getitem__(self, header):
        return self._headers[header]

    def __missing__(self, key):
        return ""

    def has_header(self, header):
        return header in self._headers

    __contains__ = has_header

    def items(self):
       return self._headers.items()

    def get(self, header, alternate=None):
        return self._headers.get(header.lower(), (None, alternate))[1]

    @property
    def content(self):
        #print("hello " + str(self._container), file=sys.stderr)
        return b"".join(self._container)

    @content.setter
    def content(self, value):
        if  isinstance(value, str):
            content = bytes(value,self._charset)
        elif isinstance(value, bytes):
            content = value
        self._container = [content]

    def __iter__(self):
        return iter(self._container)

    def __len__(self):
        return len(self._container)

