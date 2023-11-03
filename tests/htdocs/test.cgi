#!/bin/bash


printf "Content-Type: text/plain; charset=iso-8859-1\r\n"
#echo "Content-Length: 700"
printf "\r\n"
sleep 0.1

echo CGI/1.0 test script report:
echo

echo argc is $#. argv is "$*".
echo

echo SERVER_SOFTWARE = $SERVER_SOFTWARE
echo GATEWAY_INTERFACE = $GATEWAY_INTERFACE
echo SERVER_PROTOCOL = $SERVER_PROTOCOL
echo SERVER_NAME = $SERVER_NAME
echo SERVER_ADDR = $SERVER_ADDR
echo SERVER_PORT = $SERVER_PORT
echo REMOTE_HOST = $REMOTE_HOST
echo REMOTE_ADDR = $REMOTE_ADDR
echo REQUEST_METHOD = $REQUEST_METHOD
echo SCHEME = "$REQUEST_SCHEME"
if [ -n "$HTTPS" ]; then
	echo HTTPS = on
fi
echo URI = "$REQUEST_URI"
echo QUERY_STRING = "$QUERY_STRING"
echo HTTP_ACCEPT = "$HTTP_ACCEPT"
echo PATH_INFO = "$PATH_INFO"
echo PATH_TRANSLATED = "$PATH_TRANSLATED"
echo DOCROOT = "$DOCUMENT_ROOT"
echo SCRIPT_FILENAME = "$SCRIPT_FILENAME"
echo SCRIPT_NAME = "$SCRIPT_NAME"
if [ -n "$REMOTE_USER" ]; then
	echo USER = $REMOTE_USER
fi
if [ -n "$AUTH_TYPE" ]; then
	echo AUTH_TYPE = $AUTH_TYPE
fi
echo CONTENT_TYPE = $CONTENT_TYPE
echo CONTENT_LENGTH = $CONTENT_LENGTH

echo CONTENT:
echo > /tmp/ouistiti.content.txt
read CONTENT
while [ -n "$CONTENT" ]; do
echo $CONTENT >> /tmp/ouistiti.content.txt
echo $CONTENT
read CONTENT
done
