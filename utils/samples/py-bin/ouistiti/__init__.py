class Settings:
	DEBUG = False
	DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
	USE_X_FORWARDED_HOST = False
	ALLOWED_HOSTS = None
	SECURE_PROXY_SSL_HEADER = False
	FILE_UPLOAD_HANDLERS = None
	DATA_UPLOAD_MAX_MEMORY_SIZE = None
	DEFAULT_CHARSET = "utf-8"

settings = Settings()

from ouistiti.request import (
    HttpHeaders,
    HttpRequest,
    QueryDict,
    RawPostDataException,
    UnreadablePostError,
)
from ouistiti.response import (
    BadHeaderError,
    FileResponse,
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseBase,
    HttpResponseForbidden,
    HttpResponseGone,
    HttpResponseNotAllowed,
    HttpResponseNotFound,
    HttpResponseNotModified,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
    HttpResponseServerError,
    StreamingHttpResponse,
)

__all__ = [
    "SimpleCookie",
    "parse_cookie",
    "HttpHeaders",
    "HttpRequest",
    "QueryDict",
    "RawPostDataException",
    "UnreadablePostError",
    "HttpResponse",
    "HttpResponseBase",
    "StreamingHttpResponse",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "HttpResponseNotModified",
    "HttpResponseBadRequest",
    "HttpResponseForbidden",
    "HttpResponseNotFound",
    "HttpResponseNotAllowed",
    "HttpResponseGone",
    "HttpResponseServerError",
    "Http404",
    "BadHeaderError",
    "FileResponse",
]
