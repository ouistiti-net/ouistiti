/*****************************************************************************
 * mod_cors.c: webstream server module
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <wait.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_cors.h"

typedef struct _mod_cors_s _mod_cors_t;
typedef struct _mod_cors_ctx_s _mod_cors_ctx_t;

typedef int (*socket_t)(mod_cors_t *config, char *filepath);

struct _mod_cors_s
{
	mod_cors_t *config;
	socket_t socket;
	const char *methods;
};

static const char str_cors[] = "cors";

static int _cors_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const _mod_cors_t *mod = (_mod_cors_t *)arg;

	const char *origin = httpmessage_REQUEST(request, "Origin");
	const char *host = httpmessage_REQUEST(request, "Host");
	if (origin && origin[0] != '\0' && (utils_searchexp(origin, mod->config->origin, NULL) == ESUCCESS))
	{
		httpmessage_addheader(response, "Access-Control-Allow-Origin", origin, -1);
		const char *method;
		method = httpmessage_REQUEST(request, "method");
		const char *methods = method;
		if (mod->methods && mod->methods[0] != '\0')
			methods = mod->methods;
		const char *ac_request;
		ac_request = httpmessage_REQUEST(request, "Access-Control-Request-Method");
		if (ac_request && ac_request[0] != '\0')
		{
			httpmessage_addheader(response, "Access-Control-Allow-Methods", methods, -1);
		}
		ac_request = httpmessage_REQUEST(request, "Access-Control-Request-Headers");
		if (ac_request && ac_request[0] != '\0')
		{
			httpmessage_addheader(response, "Access-Control-Allow-Headers", ac_request, -1);
		}
		httpmessage_addheader(response, "Access-Control-Allow-Credentials", STRING_REF("true"));
		if (!strcmp(method, str_options))
		{
			ret = ESUCCESS;
		}
	}
	else if (origin && origin[0] != '\0' && httpmessage_isprotected(request) && (strstr(origin, host) == NULL))
	{
		httpmessage_result(response, 405);
		ret = ESUCCESS;
	}
	else
	{
		httpmessage_addheader(response, "Vary", STRING_REF("Origin"));
	}
	return ret;
}

static void *_mod_cors_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	_mod_cors_t *mod = (_mod_cors_t *)arg;

	/**
	 * Methods must be set here, because other modules may append new methods to the server.
	 */
	mod->methods = httpserver_INFO(httpclient_server(clt), "methods");
	httpclient_addconnector(clt, _cors_connector, mod, CONNECTOR_FILTER, str_cors);

	return mod;
}

static void _mod_cors_freectx(void *arg)
{
}

#ifdef FILE_CONFIG
static void *cors_config(config_setting_t *iterator, server_t *server)
{
	mod_cors_t *config = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *config_set = config_setting_get_member(iterator, "cors");
#else
	const config_setting_t *config_set = config_setting_lookup(iterator, "cors");
#endif
	if (config_set)
	{
		config = calloc(1, sizeof(*config));
		config_setting_lookup_string(config_set, "origin", (const char **)&config->origin);
	}
	return config;
}
#else
static void *cors_config(void *iterator, server_t *server)
{
	return NULL;
}
#endif

static void *mod_cors_create(http_server_t *server, mod_cors_t *config)
{
	if (config == NULL)
		return NULL;

	_mod_cors_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;

	httpserver_addmethod(server, METHOD(str_options), 0);
	httpserver_addmod(server, _mod_cors_getctx, _mod_cors_freectx, mod, str_cors);
	return mod;
}

static void mod_cors_destroy(void *data)
{
	_mod_cors_t *mod = (_mod_cors_t *)data;
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	free(data);
}

const module_t mod_cors =
{
	.name = str_cors,
	.configure = (module_configure_t)&cors_config,
	.create = (module_create_t)&mod_cors_create,
	.destroy = &mod_cors_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_cors")));
#endif
