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
        self["Content-Type"] = content_type
        if content and len(content) > 0:
            self.content = content
        else:
            self.status_code = 204
        self.status_code = int(status)

    def close(self):
        self.closed = True

    def __setitem__(self, header, value):
        if header.lower() == "content-length" and self.closed:
            return
        if header.lower() == "location":
            self.status_code = 302
        if isinstance(value, str):
            value.encode("latin-1")
        elif isinstance(header, bytes):
            value = value.decode("latin-1")
        else:
            value = str(value)
        if isinstance(header, bytes):
            key = header.decode("ascii")
        elif isinstance(header, str):
            header.encode("ascii")
            key = header
        self._headers[header.lower()] = (key, value)

    def __delitem__(self, header):
        self._headers.pop(header.lower(), False)

    def __getitem__(self, header):
        if header.lower() == "content-length" and not self.closed and len(self._container) > 0:
            self.__delitem__(header)
            content_length = 0
            for contentpart in self._container:
                content_length += len(contentpart)
            self.__setitem__(header, str(content_length))
            self.closed = True
        if header.lower() in self._headers:
            return self._headers[header.lower()][1]
        else:
            print("item " + str(header) + " not found", file=sys.stderr)
            return ""

    def __missing__(self, key):
        return ""

    def has_header(self, header):
        return header.lower() in self._headers

    __contains__ = has_header

    def items(self):
        return self._headers.values()

    def get(self, header, alternate=None):
        return self._headers.get(header.lower(), (None, alternate))[1]

    def __iter__(self):
        return iter(self._headers)

    def __len__(self):
        return len(self._headers)

    @property
    def content(self):
        #print("hello " + str(self._container), file=sys.stderr)
        return self._container

    @content.setter
    def content(self, value):
        if  isinstance(value, str):
            content = bytes(value,self._charset)
        elif isinstance(value, bytes):
            content = value
        self._container = [content]

