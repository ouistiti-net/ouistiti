from ouistiti import HttpResponse, HttpRequest

def echo(request):
	content_type=""
	if "CONTENT_TYPE" in request.META:
		content_type = request.META["CONTENT_TYPE"]
	if "multipart/form-data" not in content_type:
		message = request.body
	else:
		message = b"Long contents inside Request are not supported"
		content_type = "text/plain"
	response = HttpResponse(message, content_type=content_type)
	response["Content-Length"] = len(response.content)
	return response
