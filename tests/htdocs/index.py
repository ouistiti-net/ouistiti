from ouistiti import HttpResponse, HttpRequest
#import os

#os.environ.setdefault('DJANGO_SETTINGS_MODULE', "settings")
#from django.http import HttpResponse, HttpRequest

def index(request):
	response = HttpResponse(bytes("Hello world " + request.scheme + " " + request.META["QUERY_STRING"] + "\n", 'utf-8'), content_type="text/plain")
	response["Content-Length"]
	response["X-Test"] = "test"
	return response

if __name__ == "__main__":
	request = HttpRequest()
	request.META["QUERY_STRING"] = "Hello World"
	response = index(request)
	print(response["Content-Type"])
	print(response.content)
