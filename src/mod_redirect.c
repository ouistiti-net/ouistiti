/*****************************************************************************
 * mod_redirect.c: Redirect the request on 404 error
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
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_redirect.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define redirect_dbg(...)

#ifndef RESULT_204
#define RESULT_204 204
#endif

typedef struct _mod_redirect_s _mod_redirect_t;

static int _mod_redirect_connector(void *arg, http_message_t *request, http_message_t *response);
static int _mod_redirect_connectorerror(void *arg, http_message_t *request, http_message_t *response);

static const char str_redirect[] = "redirect";

struct _mod_redirect_s
{
	mod_redirect_t	*config;
	int result;
};

#ifdef FILE_CONFIG
static int redirect_mode(const char *mode)
{
	int options = 0;
	if (utils_searchexp("generate_204", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_GENERATE204;
	}
	if (utils_searchexp("hsts", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_HSTS;
	}
	if (utils_searchexp("temporary", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_TEMPORARY;
	}
	else if (utils_searchexp("permanently", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_PERMANENTLY;
	}
	if (utils_searchexp("error", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_ERROR;
	}
	if (utils_searchexp("query", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_QUERY;
	}
	return options;
}

static mod_redirect_link_t *redirect_linkconfig(config_setting_t *iterator)
{
	mod_redirect_link_t *link = NULL;
	char *mode = NULL;
	int options = 0;

	link = calloc(1, sizeof(*link));
	config_setting_t *originset = config_setting_lookup(iterator, "origin");
	if (config_setting_is_number(originset))
	{
		link->result = config_setting_get_int(originset);
		if (link->result == 204)
			options |= REDIRECT_GENERATE204;
		else
			options |= REDIRECT_ERROR;
	}
	else
		link->origin = config_setting_get_string(originset);

	config_setting_lookup_string(iterator, "options", (const char **)&mode);
	link->options = redirect_mode(mode);
	link->options |= options;

	const char *destination = NULL;
	config_setting_lookup_string(iterator, "destination", (const char **)&destination);
	if (destination != NULL && destination[0] != '\0')
		link->destination = destination;

	const char *defaultpage= NULL;
	config_setting_lookup_string(iterator, "defaultpage", (const char **)&defaultpage);
	if (defaultpage != NULL && defaultpage[0] != '\0')
		link->defaultpage = defaultpage;
	return link;
}

static int redirect_linksconfig(config_setting_t *configlinks, mod_redirect_t *conf)
{
	conf->options |= REDIRECT_LINK;
	int count = config_setting_length(configlinks);
	int i;
	for (i = 0; i < count; i++)
	{
		config_setting_t *iterator = config_setting_get_elem(configlinks, i);
		if (iterator)
		{
			mod_redirect_link_t *link = redirect_linkconfig(iterator);
			if (link != NULL)
			{
				link->next = conf->links;
				conf->links = link;
			}
		}
	}
	return count;
}

static void *redirect_config(config_setting_t *iterator, server_t *server)
{
	mod_redirect_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "redirect");
#else
	config_setting_t *config = config_setting_lookup(iterator, "redirect");
#endif
	if (config)
	{
		conf = calloc(1, sizeof(*conf));
		char *mode = NULL;
		config_setting_lookup_string(config, "options", (const char **)&mode);
		conf->options = redirect_mode(mode);

		config_setting_t *configlinks = config_setting_lookup(config, "links");
		if (configlinks)
		{
			redirect_linksconfig(configlinks, conf);
		}
	}
	return conf;
}
#else
static const mod_redirect_t g_redirect_config =
{
	.links = &(mod_redirect_link_t)
	{
		.origin = "^/token$",
		.options = REDIRECT_TEMPORARY,
		.next = NULL,
	},
	.options = REDIRECT_LINK,
};

static void *redirect_config(void *iterator, server_t *server)
{
	 return (void *)&g_redirect_config;
}
#endif

static void *mod_redirect_create(http_server_t *server, mod_redirect_t *config)
{
	_mod_redirect_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;
	if (config->options & REDIRECT_PERMANENTLY)
		mod->result = RESULT_301;
	else if (config->options & REDIRECT_TEMPORARY)
		mod->result = RESULT_307;
	else
		mod->result = RESULT_302;

	httpserver_addconnector(server, _mod_redirect_connector, mod, CONNECTOR_DOCFILTER, str_redirect);
	httpserver_addconnector(server, _mod_redirect_connectorerror, mod, CONNECTOR_ERROR, str_redirect);
	return mod;
}

void mod_redirect_destroy(void *arg)
{
	_mod_redirect_t *mod = (_mod_redirect_t *)arg;
#ifdef FILE_CONFIG
	mod_redirect_t *config = mod->config;
	mod_redirect_link_t *link = config->links;
	while (link != NULL)
	{
		mod_redirect_link_t *next = link->next;
		free(link);
		link = next;
	}
	free(config);
#endif
	free(mod);
}

static int _mod_redirect_connector404(_mod_redirect_t *mod, http_message_t *request,
									http_message_t *response, mod_redirect_link_t *link,
									const char *uri, size_t urilen)
{
	int ret = ECONTINUE;
	/**
	 * many link on 404, each one check the path and has different defaultpage
	 */
	if (link->origin && utils_searchexp(uri, link->origin, NULL) != ESUCCESS)
	{
		return ret;
	}
	/**
	 * defaultpage is set and the uri points on a directory
	 */
	if (link->defaultpage != NULL && (uri[0] == '\0' || uri[urilen - 1] == '/'))
	{
		httpmessage_addheader(response, str_location, STRING_REF(""));
		if (urilen > 0 && uri[0] != '/')
		{
			httpmessage_appendheader(response, str_location, STRING_REF("/"));
		}
		if (urilen > 0)
			httpmessage_appendheader(response, str_location, uri, urilen);
		if (link->defaultpage[0] != '/' && (urilen == 0 || uri[urilen - 1] != '/'))
		{
			httpmessage_appendheader(response, str_location, STRING_REF("/"));
		}
		httpmessage_appendheader(response, str_location, link->defaultpage, -1);
		ret = ESUCCESS;
	}
	/**
	 * remove circular redicrection
	 */
	else if (link->destination != NULL &&
			utils_searchexp(uri, link->destination, NULL) != ESUCCESS)
	{
		httpmessage_addheader(response, str_location, link->destination, -1);
		ret = ESUCCESS;
	}
	if (ret == ESUCCESS)
	{
		httpmessage_result(response, RESULT_301);
	}
	return ret;
}

static int _mod_redirect_destination(_mod_redirect_t *mod, mod_redirect_link_t *link,
									http_message_t *request, http_message_t *response,
									const char *path_info)
{
	httpmessage_addheader(response, str_location, link->destination, -1);
	char sep = '?';
	if (strchr(link->destination, '?'))
		sep = '&';
	if (path_info != NULL)
	{
		httpmessage_appendheader(response, str_location, path_info, -1);
		if (strchr(path_info, '?'))
			sep = '&';
	}
	redirect_dbg("redirect: Location from destination %s", link->destination);
	if (link->options & REDIRECT_QUERY)
	{
		const char *query = NULL;
		size_t length = httpmessage_REQUEST2(request, "query", &query);
		if (length > 0)
		{
			httpmessage_appendheader(response, str_location, &sep, 1);
			httpmessage_appendheader(response, str_location, query, length);
		}
	}
	return ESUCCESS;
}

static int _mod_redirect_connectorlink(_mod_redirect_t *mod, http_message_t *request,
									http_message_t *response, mod_redirect_link_t *link,
									const char *uri, size_t urilen)
{
	int ret = ECONTINUE;
	const char *path_info = NULL;

	if (link->origin && utils_searchexp(uri, link->origin, &path_info) == ESUCCESS)
	{
		int result = mod->result;
		if (link->options & REDIRECT_PERMANENTLY)
			result = RESULT_301;
		else if (link->options & REDIRECT_TEMPORARY)
			result = RESULT_307;

		if (link->destination != NULL &&
				utils_searchexp(uri, link->destination, NULL) != ESUCCESS)
		{
			ret = _mod_redirect_destination(mod, link, request, response, path_info);
		}
		else if (link->options & REDIRECT_QUERY)
		{
			const char *redirect = NULL;
			size_t length = httpmessage_parameter(request, "redirect_uri", &redirect);
			char *decode = utils_urldecode(redirect, length);
			if (decode != NULL)
			{
				redirect_dbg("redirect: Location from query %s", decode);
				httpmessage_addheader(response, str_location, decode, strlen(decode));
				free(decode);
			}
			ret = ESUCCESS;
		}
		if (ret == ESUCCESS)
		{
			httpmessage_result(response, result);
		}
	}
	return ret;
}

static int _mod_redirect_hsts(_mod_redirect_t *mod, http_message_t *request, http_message_t *response,
			const char *scheme, int schemelen, const char *uri, int urilen)
{
	const char *host = NULL;
	size_t hostlen = httpmessage_REQUEST2(request, "host", &host);
	if (hostlen > 0)
	{
		httpmessage_addheader(response, str_location, scheme, schemelen);
		httpmessage_appendheader(response, str_location, STRING_REF("://"));
		httpmessage_appendheader(response, str_location, host, hostlen);
#if 0
		const char *port = NULL;
		size_t portlen = httpmessage_REQUEST2(request, "port", &port);
		if (portlen >0)
		{
			httpmessage_appendheader(response, str_location, STRING_REF(":"));
			httpmessage_appendheader(response, str_location, port, portlen);
		}
#endif
		httpmessage_appendheader(response, str_location, uri, urilen);
		httpmessage_addheader(response, "Vary", STRING_REF(str_upgrade_insec_req));
		httpmessage_result(response, RESULT_301);
		return ESUCCESS;
	}
	return EREJECT;
}

static int _mod_redirect_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_redirect_t *mod = (_mod_redirect_t *)arg;
	mod_redirect_t *config = mod->config;
	const char *uri = NULL;
	int urilen = httpmessage_REQUEST2(request, "uri", &uri);

	if (config->options & REDIRECT_HSTS)
	{
		const char *scheme = httpmessage_REQUEST(request, "scheme");
		const char *upgrade = httpmessage_REQUEST(request, str_upgrade_insec_req);
		if (strcmp(scheme, str_https) && !strcmp(upgrade, "1"))
		{
			return _mod_redirect_hsts(mod, request, response, str_https, sizeof(str_https) - 1, uri, urilen);
		}
		else
		{
			httpmessage_addheader(response, "Strict-Transport-Security", STRING_REF("max-age=31536000; includeSubDomains"));
		}
	}
	if (config->options & REDIRECT_GENERATE204)
	{
		if (utils_searchexp(uri, "generate_204", NULL) == ESUCCESS)
		{
			httpmessage_result(response, RESULT_204);
			return ESUCCESS;
		}
	}
	if (config->options & REDIRECT_LINK)
	{
		mod_redirect_link_t *link = config->links;
		while (link != NULL)
		{
			int ret = ECONTINUE;
			if (link->origin && utils_searchexp(uri, link->origin, NULL) == ESUCCESS)
			{
				if (link->options & REDIRECT_GENERATE204)
				{
					httpmessage_result(response, RESULT_204);
					ret = ESUCCESS;
				}
				if (ret == ECONTINUE)
					ret = _mod_redirect_connectorlink(mod, request, response, link, uri, urilen);
			}
			if (ret != ECONTINUE)
			{
				return ret;
			}
			link = link->next;
		}
	}
	return EREJECT;
}

static int _mod_redirect_connectorerror(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_redirect_t *mod = (_mod_redirect_t *)arg;
	mod_redirect_t *config = mod->config;
	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request, "uri", &uri);
	int result = httpmessage_result(response, 0);

	mod_redirect_link_t *link = config->links;
	while (link != NULL)
	{
		int ret = ECONTINUE;
		if (result == 404 && link->result == result)
			ret = _mod_redirect_connector404(mod, request, response, link, uri, urilen);
		if ((ret == ECONTINUE) && (link->options & REDIRECT_ERROR) && (link->result == result))
		{
			int result = mod->result;
			if (link->options & REDIRECT_PERMANENTLY)
				result = RESULT_301;
			else if (link->options & REDIRECT_TEMPORARY)
				result = RESULT_307;

			if (link->destination != NULL &&
					utils_searchexp(uri, link->destination, NULL) != ESUCCESS)
			{
				httpmessage_addheader(response, str_location, link->destination, -1);
				httpmessage_result(response, result);
				ret = ESUCCESS;
			}
		}
		if (ret != ECONTINUE)
		{
			return ret;
		}
		link = link->next;
	}
	return EREJECT;
}

const module_t mod_redirect =
{
	.name = str_redirect,
	.configure = (module_configure_t)&redirect_config,
	.create = (module_create_t)&mod_redirect_create,
	.destroy = &mod_redirect_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_redirect")));
#endif
