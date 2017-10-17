/*****************************************************************************
 * mod_filestorage.c: callbacks and management of files
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <signal.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_static_file.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static int filestorage_checkname(static_file_connector_t *private, http_message_t *response)
{
	if (private->path_info[0] == '.')
	{
		warn("file name not allowed %s", private->path_info);
#if defined RESULT_403
		httpmessage_result(response, RESULT_403);
#else
		httpmessage_result(response, RESULT_400);
#endif
		free(private->filepath);
		private->filepath = NULL;
		free(private->path_info);
		private->path_info = NULL;
		return ESUCCESS;
	}
	return EREJECT;
}

int filestorage_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->path_info == NULL)
		return ret;
	char *method = httpmessage_REQUEST(request, "method");
	if (!strcmp(method, "PUT"))
	{
		if (filestorage_checkname(private, response) == ESUCCESS)
			return ESUCCESS;
		if (private->fd == 0)
		{
			private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", NULL);
			int length = strlen(private->path_info);
			if (private->path_info[length - 1] == '/')
			{
				httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"name\":\"", -1);
				httpmessage_appendcontent(response, private->path_info, -1);
				httpmessage_appendcontent(response, "\",\"result\":\"", -1);
				if (mkdir(private->filepath, 0777) > 0)
				{
					err("directory creation not allowed %s", private->path_info);
					httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_403
					httpmessage_result(response, RESULT_403);
#else
					httpmessage_result(response, RESULT_400);
#endif
				}
				else
				{
					warn("directory creation %s", private->path_info);
					httpmessage_appendcontent(response, "OK\"}", -1);
				}
				ret = ESUCCESS;
				free(private->filepath);
				private->filepath = NULL;
				free(private->path_info);
				private->path_info = NULL;
			}
			else
			{
				private->fd = open(private->filepath, O_WRONLY | O_CREAT, 0644);
				if (private->fd > 0)
				{
					ret = EINCOMPLETE;
				}
				else
				{
					err("file creation not allowed %s", private->path_info);
					httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"result\":\"KO\",\"name\":\"", -1);
					httpmessage_appendcontent(response, private->path_info, -1);
					httpmessage_appendcontent(response, "\"}", -1);
#if defined RESULT_403
					httpmessage_result(response, RESULT_403);
#else
					httpmessage_result(response, RESULT_400);
#endif
					ret = ESUCCESS;
					private->fd = 0;
					free(private->filepath);
					private->filepath = NULL;
					free(private->path_info);
					private->path_info = NULL;
				}
			}
		}
		/**
		 * we are into PRECONTENT, the data is no yet available
		 * Then the first loop as to complete on the opening
		 */
		else if (private->fd > 0)
		{
			char *input;
			int inputlen;
			int rest;
			rest = httpmessage_content(request, &input, &inputlen);
			if (inputlen > 0 && rest > 0)
			{
				write(private->fd, input, inputlen);
				ret = EINCOMPLETE;
			}
			else
			{
				httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"result\":\"OK\",\"name\":\"", -1);
				httpmessage_appendcontent(response, private->path_info, -1);
				httpmessage_appendcontent(response, "\"}", -1);
				close(private->fd);
				private->fd = 0;
				ret = ESUCCESS;
				free(private->filepath);
				private->filepath = NULL;
				free(private->path_info);
				private->path_info = NULL;
			}
		}
	}
	else if (!strcmp(method, "POST") && private->fd == 0)
	{
		if (filestorage_checkname(private, response) == ESUCCESS)
			return ESUCCESS;
		private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", NULL);
		warn("change %s", private->filepath);
		httpmessage_addcontent(response, "text/json", "{\"method\":\"POST\",\"result\":\"OK\",\"name\":\"", -1);
		httpmessage_appendcontent(response, private->path_info, -1);
		httpmessage_appendcontent(response, "\"}", 2);
		private->fd = 0;
		ret = ESUCCESS;
		free(private->filepath);
		private->filepath = NULL;
		free(private->path_info);
		private->path_info = NULL;
	}
	else if (!strcmp(method, "DELETE") && private->fd == 0)
	{
		if (filestorage_checkname(private, response) == ESUCCESS)
			return ESUCCESS;
		private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", NULL);
		httpmessage_addcontent(response, "text/json", "{\"method\":\"DELETE\",\"name\":\"", -1);
		httpmessage_appendcontent(response, private->path_info, -1);
		httpmessage_appendcontent(response, "\",\"result\":\"", -1);
		if (unlink(private->filepath) > 0)
		{
			err("file removing not allowed %s", private->path_info);
			httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_403
			httpmessage_result(response, RESULT_403);
#else
			httpmessage_result(response, RESULT_400);
#endif
		}
		else
		{
			warn("remove file : %s", private->path_info);
			httpmessage_appendcontent(response, "OK\"}", -1);
		}
		private->fd = 0;
		ret = ESUCCESS;
		free(private->filepath);
		private->filepath = NULL;
		free(private->path_info);
		private->path_info = NULL;
	}
	return ret;
}
