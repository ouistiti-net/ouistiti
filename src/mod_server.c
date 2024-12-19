/*****************************************************************************
 * mod_server.c: callbacks and management of request method
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
#include <errno.h>
#include <dirent.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_server.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char str_server[] = "server";

typedef struct _mod_server_s _mod_server_t;

struct _mod_server_s
{
	mod_security_t *config;
	http_server_t *server;
};

#ifdef FILE_CONFIG
static void *mod_server_config(config_setting_t *iterator, server_t *server)
{
	mod_security_t *security = NULL;

	security = calloc(1,sizeof(*security));
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "security");
#else
	config_setting_t *config = config_setting_lookup(iterator, "security");
#endif
	if (config)
	{
		const char *options = config_setting_get_string(config);
		if (options && utils_searchexp("frame", options, NULL) == ESUCCESS)
			security->options |= SECURITY_FRAME;
		if (options && utils_searchexp("cache", options, NULL) == ESUCCESS)
			security->options |= SECURITY_CACHE;
		if (options && utils_searchexp("sniff", options, NULL) == ESUCCESS)
			security->options |= SECURITY_CONTENTTYPE;
		if (options && utils_searchexp("otherorigin", options, NULL) == ESUCCESS)
			security->options |= SECURITY_OTHERORIGIN;
	}
	return security;
}
#else
static void *mod_server_config(void *iterator, server_t *server)
{
	return NULL;
}
#endif

static int _server_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_server_t *mod = (_mod_server_t *)arg;
	mod_security_t *config = mod->config;
	int ret = EREJECT;
	int options = 0;

	const char *software = httpmessage_SERVER(request, "software");
	httpmessage_addheader(response, "Server", software, -1);
	if (config)
	{
		options = config->options;
	}
	if (!(options & SECURITY_FRAME))
	{
		httpmessage_addheader(response, "X-Frame-Options", STRING_REF("DENY"));
	}
	if (!(options & SECURITY_CACHE))
	{
		httpmessage_addheader(response, str_cachecontrol, STRING_REF("no-cache,no-store,max-age=0,must-revalidate"));
		httpmessage_addheader(response, "Pragma", STRING_REF("no-cache"));
		httpmessage_addheader(response, "Expires", STRING_REF("0"));
	}
	if (!(options & SECURITY_CONTENTTYPE))
	{
		httpmessage_addheader(response, "X-Content-Type-Options", STRING_REF("nosniff"));
	}
	if (!(options & SECURITY_OTHERORIGIN))
	{
		if (options & SECURITY_FRAME)
			httpmessage_addheader(response, "X-Frame-Options", STRING_REF("SAMEORIGIN"));

		httpmessage_addheader(response, "Referrer-Policy", STRING_REF("origin-when-cross-origin"));

#ifndef SECURITY_UNCHECKORIGIN
		const char *origin = NULL;
		size_t originlen = httpmessage_REQUEST2(request, "Origin", &origin);
		if (origin != NULL)
		{
			const char *host = NULL;
			size_t hostlen = httpserver_INFO2(mod->server, "hostname", &host);
			const char *refererhost = strstr(origin, "://");
			if (refererhost == NULL)
				refererhost = origin;
			else
				originlen -= refererhost - origin;
			char *end = strchr(refererhost, '/');
			int len;
			if (end == NULL)
				len = originlen;
			else
				len = end - refererhost;
			if ((hostlen != len) || strncmp(refererhost, host, len))
			{
				httpmessage_result(response, RESULT_403);
				ret = ESUCCESS;
			}
		}
#else
# warning "request origin is not check"
#endif
	}
	return ret;
}

static void *mod_server_create(http_server_t *server, void *config)
{
	_mod_server_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->server = server;
	httpserver_addconnector(server, _server_connector, mod, CONNECTOR_FILTER, str_server);

	return mod;
}

static void mod_server_destroy(void *data)
{
	free(data);
}

const module_t mod_server =
{
	.name = str_server,
	.configure = (module_configure_t)&mod_server_config,
	.create = (module_create_t)&mod_server_create,
	.destroy = &mod_server_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_server")));
#endif
