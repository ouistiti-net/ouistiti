/*****************************************************************************
 * mod_dirlisting.c: callbacks and management of directories
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_document.h"

#ifndef S_IFMT
# define S_IFMT 0xF000
#endif

#ifndef DEBUG
# undef USE_REENTRANT
#endif

#define document_dbg(...)

typedef struct _document_connector_s document_connector_t;

#define MAX_NAMELENGTH (CONTENTCHUNK / 2)

#define DIRLISTING_HEADER "\
{\
\"method\":\"GET\",\
\"name\":\"%s\",\
\"content\":["
#define DIRLISTING_HEADER_LENGTH (sizeof(DIRLISTING_HEADER) - 2)
#define DIRLISTING_LINE "{\"name\":\"%.*s\",\"size\":\"%lu %s\",\"type\":%d,\"mime\":\"%s\"},"
#define DIRLISTING_LINE_LENGTH (sizeof(DIRLISTING_LINE))
#define DIRLISTING_FOOTER "\
{}],\
\"result\":\"%s\"\
}\n"

#ifdef DIRLISTING_MOD
static const char str_dirlisting[] = "dirlisting";
#endif

static const char *_sizeunit[] = {
	"B",
	"kB",
	"MB",
	"GB",
	"TB",
};

static int _dirlisting_connectorheader(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const char *url = private->url;
	int fdroot = private->fdroot;

	if (url[0] == '\0')
		url = ".";
	dbg("dirlisting: open /%s", private->url);
	ret = scandirat(fdroot, url, &private->ents, NULL, alphasort);
	if (ret >= 0)
	{
		private->nbents = ret;

		/**
		 * The content-length of dirlisting is unknown.
		 * Set the content-type first without content-length.
		 */
		httpmessage_addcontent(response, utils_getmime(".json"), NULL, -1);
		if (!strcmp(httpmessage_REQUEST(request, "method"), "HEAD"))
		{
			for (int i = 0; i < ret; i++)
				free(private->ents[i]);
			free(private->ents);
			private->ents = NULL;
			private->nbents = 0;
			ret = ESUCCESS;
		}
		else
		{
			const char *uri = NULL;
			size_t urilen = httpmessage_REQUEST2(request,"uri", &uri);
			char *data = calloc(1, DIRLISTING_HEADER_LENGTH + urilen + 1);
			urilen = snprintf(data, DIRLISTING_HEADER_LENGTH + urilen, DIRLISTING_HEADER, uri);
			httpmessage_appendcontent(response, data, urilen);
			free(data);
			ret = ECONTINUE;
		}
	}
	else
	{
		private->ents = NULL;
		private->nbents = 0;
		warn("dirlisting: directory not open %s %s", private->url, strerror(errno));
		httpmessage_result(response, RESULT_400);
	}

	return ret;
}

static int _dirlisting_getentity(document_connector_t *private, struct dirent *ent, http_message_t *response)
{
	int ret = EREJECT;
	if (ent == NULL)
		return EREJECT;
	document_dbg("dirlisting: dirlisting contains %s", ent->d_name);
	if (ent->d_name[0] != '.')
	{
		unsigned int length = strlen(ent->d_name);
		if (length > MAX_NAMELENGTH)
		{
			warn("dirlisting: %s file name length too long", ent->d_name);
		}
		struct stat filestat;
		fstatat(private->fdfile, ent->d_name, &filestat, 0);
		size_t size = filestat.st_size;
		if (size == -1)
		{
			err("dirlisting: %s stat error %s", ent->d_name, strerror(errno));
			return EREJECT;
		}
		int unit = 0;
		while (size > 2000)
		{
			size /= 1024;
			unit++;
		}
		const char *mime = "inode/directory";
		size_t mimelen = 15;

		if (S_ISREG(filestat.st_mode) || S_ISLNK(filestat.st_mode))
		{
			mimelen = utils_getmime2(ent->d_name, &mime);
		}
		length += mimelen;
		length += 4 + 2 + 4;
		char *data = calloc(1, DIRLISTING_LINE_LENGTH + length + 1);
		length = snprintf(data, DIRLISTING_LINE_LENGTH + length + 1, DIRLISTING_LINE, MAX_NAMELENGTH, ent->d_name, size, _sizeunit[unit], ((filestat.st_mode & S_IFMT) >> 12), mime);
		document_dbg("dirlisting: %s", data);
		httpmessage_addcontent(response, NULL, data, length);
		document_dbg("dirlisting: next");
		free(data);
		ret = ECONTINUE;
	}
	free(ent);
	return ret;
}

static int _dirlisting_connectorcontent(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	struct dirent *ent;

	errno = 0;
	while (ret == EREJECT)
	{
		document_dbg("dirlisting: entry %d", private->nbents);
		/**
		 * private->ents != NULL checked inside _dirlisting_connector
		 */
		if (private->nbents > 0)
		{
			ent = private->ents[private->nbents - 1];
			private->nbents--;
		}
		else
			ent = NULL;
		if (ent)
		{
			ret = _dirlisting_getentity(private, ent, response);
		}
		else
		{
			int length = sizeof(DIRLISTING_FOOTER);
			char *data = calloc(1, length);
			length = snprintf(data, length, DIRLISTING_FOOTER, "OK");
			httpmessage_addcontent(response, NULL, data, length);
			free(data);
			close(private->fdfile);
			private->fdfile = 0;
			ret = ECONTINUE;
		}
	}
	return ret;
}

static int _dirlisting_connectorender(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	/**
	 * the content length is unknown before the sending.
	 * We must close the socket to advertise the client.
	 */
	document_dbg("dirlisting: socket shutdown");
	httpclient_shutdown(httpmessage_client(request));
	free(private->ents);
	private->ents = NULL;
	return ESUCCESS;
}

/**
 * this function is used by mod_document and has NOT to be static
 */
int dirlisting_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	document_connector_t *private = (document_connector_t *)arg;

	if (private->ents == NULL)
	{
		ret = _dirlisting_connectorheader(private, request, response);
	}
	else if (private->fdfile > 0)
	{
		ret = _dirlisting_connectorcontent(private, request, response);
	}
	else
	{
		ret = _dirlisting_connectorender(private, request, response);
	}
	return ret;
}

#ifdef DIRLISTING_MOD
static void *_mod_dirlisting_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;
	mod_document_t *config = mod->config;
	document_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	ctx->ctl = ctl;
	httpclient_addconnector(ctl, dirlisting_connector, ctx, CONNECTOR_DOCUMENT, str_dirlisting);

	return ctx;
}

static void _mod_dirlisting_freectx(void *vctx)
{
	document_connector_t *ctx = vctx;
	if (ctx->path_info)
	{
		free(ctx->path_info);
		ctx->path_info = NULL;
	}
	free(ctx);
}

void *mod_dirlisting_create(http_server_t *server, mod_document_t *config)
{
	_mod_document_mod_t *mod = calloc(1, sizeof(*mod));

	if (config == NULL)
		return NULL;

	mod->config = config;
	httpserver_addmod(server, _mod_dirlisting_getctx, _mod_dirlisting_freectx, mod, str_dirlisting);

	return mod;
}

void mod_dirlisting_destroy(void *data)
{
	free(data);
}
const module_t mod_dirlisting =
{
	.name = str_dirlisting,
	.create = (module_create_t)&mod_dirlisting_create,
	.destroy = &mod_dirlisting_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_dirlisting")));
#endif
#endif
