/*****************************************************************************
 * mod_document.c: callbacks and management of files
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
#include <errno.h>
#include <time.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_document.h"
#include "mod_auth.h"

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT         0x800   /* Suppress terminal automount traversal */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname */
#endif

#define document_dbg(...)

/**
 * transfer function for getfile_connector
 */
static int mod_send_read(document_connector_t *private, http_message_t *response);
#ifdef SENDFILE
extern int mod_send_sendfile(document_connector_t *private, http_message_t *response);
#endif
static int _mime_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_document[] = "document";

/**
 * USE_PRIVATE is used to keep a sample of cade which uses
 * the httpmessage_private function
 */
typedef struct _document_connector_s document_connector_t;

int mod_send(document_connector_t *private, http_message_t *response);

static void _document_close(document_connector_t *private)
{
	if (private->fdfile > 0)
		close(private->fdfile);
	private->fdfile = 0;
	if (private->fdroot > 0)
		close(private->fdroot);
	private->fdroot = 0;
	private->func = NULL;
}

#ifdef DOCUMENTHOME
static int _document_dochome(_mod_document_mod_t *mod,
		http_message_t *request, const char **uri)
{
	int fdroot = -1;

	while ((*uri)[0] == '/') (*uri)++;

	const char *user = auth_info(request, STRING_REF(str_user));
	const char *home = auth_info(request, STRING_REF(str_home));
	while ((home[0] == '/' || home[0] == '.') && home[0] != '\0') home++;
	if (home[0] == '\0')
		home = user;
	//check leading characters on user
	while ((home[0] == '/' || home[0] == '.') && home[0] != '\0') home++;
	mkdirat(mod->fdhome, home, 0640);
	fdroot = openat(mod->fdhome, home, O_DIRECTORY);
	if (fdroot == -1)
	{
		err("document: folder error %s", strerror(errno));
	}
	else
	{
		document_dbg("document: home directory is %s", home);
	}
	return fdroot;
}
#endif

static int _document_docroot(_mod_document_mod_t *mod,
		http_message_t *request, const char **uri)
{
	int fdroot = mod->fdroot;
	document_dbg("document: root directory is %s", mod->config->docroot);

	return fdroot;
}

static int _document_getdefaultpage(_mod_document_mod_t *mod, int fdroot, const char *url, http_message_t *response)
{
	const mod_document_t *config = mod->config;
	int fdfile = openat(fdroot, config->defaultpage, O_RDONLY);
	if (fdfile > 0)
	{
		document_dbg("document: move to %s/%s", url, config->defaultpage);
		/**
		 * Check uri is only one character.
		 * It should be "/"
		 */
		if (url[0] != '\0')
			httpmessage_addheader(response, str_location, STRING_REF("/"));
		else
			httpmessage_addheader(response, str_location, STRING_REF(""));
		httpmessage_appendheader(response, str_location, url, -1);
		httpmessage_appendheader(response, str_location, STRING_REF("/"));
		httpmessage_appendheader(response, str_location, config->defaultpage, -1);
	}
	return fdfile;
}

static int _document_getconnnectorget(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen, const char **mime,
		http_message_t *request, http_message_t *response,
		http_connector_t *connector)
{
	const mod_document_t *config = mod->config;
	struct stat filestat;
	int fdfile = -1;
	if (faccessat(fdroot, url, F_OK, 0) == -1)
	{
		if (url[0] != '\0' && url[urllen - 1] != '/')
			return fdfile;
	}
	if (fstatat(fdroot, url, &filestat, AT_EMPTY_PATH | AT_NO_AUTOMOUNT) == -1)
	{
		return 0;
	}
	if (S_ISDIR(filestat.st_mode))
	{
		document_dbg("document: %s is directory", url);
		if (url[0] != '\0')
			fdfile = openat(fdroot, url, O_DIRECTORY);
		else
			fdfile = openat(fdroot, ".",  O_DIRECTORY);
#ifdef DIRLISTING
		const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
		if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL) &&
			(config->options & DOCUMENT_DIRLISTING))
		{
			*connector = dirlisting_connector;
		}
		else
#endif
		if (config->defaultpage != NULL)
		{
			fdroot = fdfile;
			*connector = getfile_connector;
			fdfile = openat(fdroot, config->defaultpage, O_RDONLY);
			close(fdroot);
			*mime = utils_getmime(config->defaultpage);
		}
		else
		{
			close(fdfile);
			return -1;
		}
	}
	else if (filestat.st_size == 0)
	{
		document_dbg("document: empty file");
#if defined(RESULT_204)
		httpmessage_result(response, RESULT_204);
#endif
		fdfile = 0;
		errno = 0;
	}
	else
	{
		*connector = getfile_connector;
		fdfile = openat(fdroot, url, O_RDONLY);
		*mime = utils_getmime(url);
	}
	return fdfile;
}

static int _document_getconnnectorheader(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen, const char **mime,
		http_message_t *request, http_message_t *response,
		http_connector_t *connector)
{
	int fdfile = _document_getconnnectorget(mod, fdroot, url, urllen,
				mime, request, response, connector);
	*connector = NULL;
	return fdfile;
}

static int _document_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	_mod_document_mod_t *mod = private->mod;
	http_connector_t connector = NULL;
	const mod_document_t *config = mod->config;

	const char *uri = NULL;
	int urilen = httpmessage_REQUEST2(request,"uri", &uri);

	if (htaccess_check(&mod->config->htaccess, uri, NULL) == EREJECT)
	{
		document_dbg("document: %s forbidden extension", uri);
		/**
		 * Another module may have the same docroot and
		 * accept the name of the uri.
		 * The module has not to return an error.
		 */
		return  EREJECT;
	}
	int fdroot = EREJECT;
	while (uri[0] == '/')
	{
		uri++;
		urilen--;
	}
#ifdef DOCUMENTHOME
	if (uri[0] == '~' && mod->fdhome != -1)
	{
		uri++;
		fdroot = _document_dochome(mod, request, &uri);
	}
	else
#endif
		fdroot = _document_docroot(mod, request, &uri);
	if (fdroot == EREJECT)
	{
		httpmessage_result(response, RESULT_404);
		return  ESUCCESS;
	}
	/// without dup otherwise two successive requests fail (test049)
	fdroot = dup(fdroot);

	int fdfile = -1;
	const char *mime = NULL;

	int type = 0;
	const char *method = httpmessage_REQUEST(request, "method");
#ifdef DOCUMENTREST
	if ((config->options & DOCUMENT_REST) && !strcmp(method, str_put))
	{
		fdfile = _document_getconnnectorput(mod, fdroot, uri, urilen,
					&mime, request, response, &connector);
		type |= DOCUMENT_REST;
	}
	else if ((config->options & DOCUMENT_REST) && !strcmp(method, str_post))
	{
		fdfile = _document_getconnnectorpost(mod, fdroot, uri,urilen,
					&mime, request, response, &connector);
		type |= DOCUMENT_REST;
	}
	else if ((config->options & DOCUMENT_REST) && !strcmp(method, str_delete))
	{
		fdfile = _document_getconnnectordelete(mod, fdroot, uri, urilen,
					&mime, request, response, &connector);
		type |= DOCUMENT_REST;
	}
	else
#endif
	if (!strcmp(method, str_get))
	{
		fdfile = _document_getconnnectorget(mod, fdroot, uri, urilen,
					&mime, request, response, &connector);
	}
	else if (!strcmp(method, str_head))
	{
		fdfile = _document_getconnnectorheader(mod, fdroot, uri, urilen,
					&mime, request, response, &connector);
	}
	else
	{
		close(fdroot);
		return EREJECT;
	}
	if (fdfile == 0)
	{
		if (errno > 0)
		{
			switch (errno)
			{
#if defined RESULT_403
			case EACCES:
				httpmessage_result(response, RESULT_403);
			break;
#endif
#if defined RESULT_409
			case EBUSY:
			case EEXIST:
				httpmessage_result(response, RESULT_409);
			break;
#endif
#if defined RESULT_404
			case ENOENT:
				httpmessage_result(response, RESULT_404);
			break;
#endif
			default:
				httpmessage_result(response, RESULT_400);
			}
		}
		close(fdroot);
		return  ESUCCESS;
	}
	if (fdfile < 0)
	{
		document_dbg("document: %s not exist %s", uri, strerror(errno));
		close(fdroot);
		return  EREJECT;
	}
	struct stat filestat;
	if (fstat(fdfile, &filestat) == -1)
	{
		err("document: spurious error on fstat %s", strerror(errno));
		close(fdroot);
		close(fdfile);
		httpmessage_result(response, RESULT_500);
		return ESUCCESS;
	}
	document_dbg("document: open %s", uri);

	if (S_ISDIR(filestat.st_mode))
	{
		type |= DOCUMENT_DIRLISTING;
	}

#ifndef RANGEREQUEST
	httpmessage_addheader(response, "Accept-Ranges", "none", 4);
#endif
	private->ctl = httpmessage_client(request);
	private->fdfile = fdfile;
	private->fdroot = fdroot;
	private->url = uri;
	private->mime = mime;
	private->func = connector;
	private->size = filestat.st_size;
	private->offset = 0;
	private->type = type;
#ifdef DEBUG
	clock_gettime(CLOCK_REALTIME, &private->start);
	private->datasize = private->size;
#endif
	return EREJECT;
}

int getfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	const _mod_document_mod_t *mod = private->mod;
	int ret;

	ret = mod->transfer(private, response);
	if (ret < 0)
	{
		if (errno == EAGAIN)
			return ECONTINUE;
		err("document: send %s (%d,%s)", private->url, ret, strerror(errno));
		/**
		 * it is too late to set an error here
		 */
		return EREJECT;
	}
	private->offset += ret;
	private->size -= ret;
	if (ret == 0 || private->size <= 0)
	{
#ifdef DEBUG
		struct timespec stop;
		struct timespec value;
		clock_gettime(CLOCK_REALTIME, &stop);

		value.tv_sec = stop.tv_sec - private->start.tv_sec;
		value.tv_nsec = stop.tv_nsec - private->start.tv_nsec;
		if (value.tv_sec == 0 && ((long)value.tv_nsec/1000000) == 0)
			dbg("document: (%llu bytes) %03ld ns", private->datasize, value.tv_nsec);
		else
			dbg("document: (%llu bytes) time %ld:%03ld", private->datasize, value.tv_sec, value.tv_nsec/1000000);
#endif
		warn("document: send %s", private->url);
		return ESUCCESS;
	}
	return ECONTINUE;
}

static int mod_send_read(document_connector_t *private, http_message_t *response)
{
	int ret = 0;
	int size;
	int chunksize;
	char content[CONTENTCHUNK + 1];

	/**
	 * check the size for the range support
	 * the size may be different of the real size file
	 */
	chunksize = (CONTENTCHUNK > private->size)?private->size:CONTENTCHUNK;
	size = read(private->fdfile, content, chunksize);
	if (size > 0)
	{
		ret = size;
		content[size] = 0;
		httpmessage_addcontent(response, "none", content, size);
		document_dbg("document: send %d", size);
	}
	else if (size == -1)
	{
		err("document: response() read file error %s", strerror(errno));
	}
	return ret;
}

static int _transfer_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	int ret = EREJECT;
	if (private->func)
	{
		ret = private->func(arg, request, response);
	}
	/// in case of HEAD method func is null but file is opened
	else if (private->fdfile)
		ret = ESUCCESS;
	if (ret == ESUCCESS)
	{
		_document_close(private);
	}
	return ret;
}

static int _mime_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;

	if ((private->fdfile > 0) && private->mime)
		httpmessage_addcontent(response, private->mime, NULL, private->size);

	return EREJECT;
}

static const char str_range[] = "range";
/// the freectx allows to clean the system when the socket closing
static void *_document_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	document_connector_t *private = NULL;
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;
	const mod_document_t *config = mod->config;

	private = calloc(1, sizeof(*private));

	mod->transfer = mod_send_read;
#ifdef SENDFILE
	if (config->options & DOCUMENT_SENDFILE)
	{
		mod->transfer = mod_send_sendfile;
	}
#endif
	private->mod = mod;

	// the order is important
	httpclient_addconnector(clt, _transfer_connector, private, CONNECTOR_DOCUMENT, str_document);
	httpclient_addconnector(clt, _mime_connector, private, CONNECTOR_DOCUMENT, str_document);
#ifdef RANGEREQUEST
	if (config->options & DOCUMENT_RANGE)
		httpclient_addconnector(clt, range_connector, private, CONNECTOR_DOCUMENT, str_range);
#endif
	httpclient_addconnector(clt, _document_connector, private, CONNECTOR_DOCUMENT, str_document);

	return private;
}

static void _document_freectx(void *arg)
{
	document_connector_t *private = (document_connector_t *)arg;
	_document_close(private);
	free(private);
}

#ifdef FILE_CONFIG
static int document_configpart(config_setting_t *config, server_t *server, int index, void **modconfig)
{
	int ret = ESUCCESS;
	mod_document_t * static_file = NULL;

	static_file = calloc(1, sizeof(*static_file));
	config_setting_lookup_string(config, "docroot", (const char **)&static_file->docroot);
	config_setting_lookup_string(config, "dochome", (const char **)&static_file->dochome);
	htaccess_config(config, &static_file->htaccess);
	config_setting_lookup_string(config, "defaultpage", (const char **)&static_file->defaultpage);

	char *options = NULL;
	config_setting_lookup_string(config, "options", (const char **)&options);
#ifdef DIRLISTING
	if (utils_searchexp("dirlisting", options, NULL) == ESUCCESS)
		static_file->options |= DOCUMENT_DIRLISTING;
#endif
#ifdef SENDFILE
	if (utils_searchexp("sendfile", options, NULL) == ESUCCESS)
	{
		if (!ouistiti_issecure(server))
			static_file->options |= DOCUMENT_SENDFILE;
		else
			warn("sendfile configuration is not allowed with tls");
	}
#endif
#ifdef RANGEREQUEST
	if (utils_searchexp("range", options, NULL) == ESUCCESS)
	{
		static_file->options |= DOCUMENT_RANGE;
	}
#endif
#ifdef DOCUMENTREST
	if (utils_searchexp("rest", options, NULL) == ESUCCESS)
	{
		static_file->options |= DOCUMENT_REST;
	}
#endif
#ifdef DOCUMENTHOME
	if (utils_searchexp("home", options, NULL) == ESUCCESS)
	{
		static_file->options |= DOCUMENT_HOME;
	}
#endif

	if (!strcmp(config_setting_name(config), "filestorage"))
		static_file->options |= DOCUMENT_REST;
	*modconfig = (void *)static_file;
	return ret;
}

#if LIBCONFIG_VER_MINOR < 5
#define CONFIG_SETTING_LOOKUP(iterator, entry) config_setting_get_member(iterator, entry);
#else
#define CONFIG_SETTING_LOOKUP(iterator, entry) config_setting_lookup(iterator, entry);
#endif

static int document_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int ret = ESUCCESS;
	const char *entries[] = {
		"document", "filestorage", "static_file"
	};

	config_setting_t *config = NULL;

	config = CONFIG_SETTING_LOOKUP(iterator, entries[0]);
	if (config == NULL)
		config = CONFIG_SETTING_LOOKUP(iterator, entries[1]);
	if (config == NULL)
		config = CONFIG_SETTING_LOOKUP(iterator, entries[2]);

	if (config && config_setting_is_list(config))
	{
		if (index >= config_setting_length(config))
			return EREJECT;
		config = config_setting_get_elem(config, index);
		ret = ECONTINUE;
	}
	if (config && config_setting_is_group(config))
	{
		if (document_configpart(config, server, index, modconfig) != ESUCCESS)
			ret = EREJECT;
	}
	else
		ret = EREJECT;

	return ret;
}
#else
static const mod_document_t g_document_config =
{
	.docroot = "/srv/www/htdocs",
	.defaultpage = "index.html",
	.htaccess = {
		.allow = ".html,.htm,.css,.js,.txt",
		.denyfirst = ".htaccess,.php",
	},
	.options = DOCUMENT_RANGE | DOCUMENT_DIRLISTING | DOCUMENT_REST,
};

static int document_config(void *iterator, server_t *server, int index, void **config)
{
	*config = (void *)&g_document_config;
	return ESUCCESS;
}
#endif

static void *mod_document_create(http_server_t *server, mod_document_t *config)
{
	if (!config)
	{
		err("document: configuration empty");
		return NULL;
	}
	_mod_document_mod_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->fdroot = open(config->docroot, O_DIRECTORY);
	if (mod->fdroot == -1)
	{
		err("document: docroot %s not found", config->docroot);
	}
	else
	{
		document_dbg("document: root directory is %s", config->docroot);
	}
#ifdef DOCUMENTHOME
	if (config->options & DOCUMENT_HOME)
	{
		if (config->dochome != NULL)
		{
			mod->fdhome = open(config->dochome, O_DIRECTORY);
		}
		else
		{
			mod->fdhome = mod->fdroot;
			config->dochome = config->docroot;
		}
		if (mod->fdhome == -1)
		{
			err("document: dochome %s not found", config->dochome);
		}
		else
		{
			document_dbg("document: home directory is %s", config->dochome);
		}
	}
#endif
	httpserver_addmod(server, _document_getctx, _document_freectx, mod, str_document);

#ifdef DOCUMENTREST
	if (config->options & DOCUMENT_REST)
	{
		httpserver_addmethod(server, METHOD(str_put), MESSAGE_PROTECTED | MESSAGE_ALLOW_CONTENT);
		httpserver_addmethod(server, METHOD(str_delete), MESSAGE_PROTECTED);
	}
#endif
	return mod;
}

static void mod_document_destroy(void *data)
{
	_mod_document_mod_t *mod = (_mod_document_mod_t *)data;
	free(mod->config);
	free(data);
}

const module_t mod_document =
{
	.version = 0x01,
	.name = str_document,
	.configure = (module_configure_t)&document_config,
	.create = (module_create_t)&mod_document_create,
	.destroy = &mod_document_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_document")));
#endif
