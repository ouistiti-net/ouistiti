/*****************************************************************************
 * mod_range.c: Range request support RFC 7233
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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_document.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

int range_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	if (private == NULL || private->type & DOCUMENT_DIRLISTING || !(private->fdfile > 0))
		return EREJECT;

	int filesize = private->size;

	const char *rangesize = NULL;
	const char *range = httpmessage_REQUEST(request,"Range");
	if (range != NULL && range[0] != '\0')
		rangesize = strstr(range, "bytes=");

	if (rangesize)
	{
		int offset;
		rangesize += 6;
		offset = atoi(rangesize);
		if (offset > filesize)
		{
			goto NOSATISFIABLE;
		}
		private->offset = offset;
		const char *end = strchr(rangesize, '-');
		if (end != NULL)
		{
			offset = filesize;
			if (*(end+1) >= '0' && *(end+1) <= '9')
				offset = atoi(end+1);
			if (*(end+1) == '*' || *(end+1) == '\0')
				offset = private->size - 1;
			if (offset > (filesize - 1) || offset < private->offset)
			{
				goto NOSATISFIABLE;
			}
			private->size = offset - private->offset + 1;
		}

		char range[256];
		int rangelen = snprintf(range, 256, "bytes %lu-%d/%d",
					(unsigned long)private->offset,
					offset,
					filesize);
		httpmessage_addheader(response, "Content-Range", range, rangelen);
		httpmessage_result(response, RESULT_206);

		lseek(private->fdfile, private->offset, SEEK_SET);
	}
	httpmessage_addheader(response, "Accept-Ranges", STRING_REF("bytes"));

	return EREJECT;

NOSATISFIABLE:
	{
		char range[256];
		int rangelen = snprintf(range, 256, "bytes */%d", filesize);
		httpmessage_addheader(response, "Content-Range", range, rangelen);
		httpmessage_result(response, RESULT_416);
	}
	return ESUCCESS;
}
