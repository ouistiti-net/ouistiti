/*****************************************************************************
 * mod_cgi.c: callbacks and management of connection
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *
 * follow RFC3875 : https://tools.ietf.org/html/rfc3875
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sched.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_cgi.h"

#define USE_EXECVEAT

#define cgi_dbg(...)

static const char str_cgi[] = "cgi";

typedef struct _mod_cgi_config_s _mod_cgi_config_t;
typedef struct _mod_cgi_s _mod_cgi_t;
typedef struct mod_cgi_ctx_s mod_cgi_ctx_t;

static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response);

struct mod_cgi_ctx_s
{
	enum
	{
		STATE_SETUP = 0,
		STATE_INSTART = 0x0001,
		STATE_INRUNNING = 0x0002,
		STATE_INFINISH = 0x0003,
		STATE_INMASK = 0x000F,
		STATE_OUTSTART = 0x0010,
		STATE_HEADERCOMPLETE = 0x0020,
		STATE_CONTENTCOMPLETE = 0x0030,
		STATE_OUTFINISH = 0x0040,
		STATE_OUTMASK = 0x00F0,
		STATE_END = 0x00FF,
		STATE_SHUTDOWN = 0x0100,
	} state;
	_mod_cgi_t *mod;
	http_client_t *ctl;

	string_t cgi_path;
	string_t path_info;

	pid_t pid;
	int tocgi[2];
	int fromcgi[2];

	char *chunk;
};

struct _mod_cgi_s
{
	http_server_t *server;
	mod_cgi_config_t *config;
	int rootfd;
};

#ifdef FILE_CONFIG
static int cgi_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configcgi = config_setting_get_member(iterator, "cgi");
#else
	config_setting_t *configcgi = config_setting_lookup(iterator, "cgi");
#endif
	if (configcgi)
	{
		cgienv_config(iterator, configcgi, server, (mod_cgi_config_t **)modconfig, NULL);
	}
	return ESUCCESS;
}
#else
static const mod_cgi_config_t g_cgi_config =
{
	.docroot = "/srv/www""/cig-bin",
	.htaccess = {
		.denylast = "*",
		.allow = "*.cgi*",
	},
};

static int cgi_config(void *iterator, server_t *server, int index, void **config)
{
	*config = (void *)&g_cgi_config;
	return ESUCCESS;
}
#endif

static void *mod_cgi_create(http_server_t *server, mod_cgi_config_t *modconfig)
{
	_mod_cgi_t *mod;

	if (!modconfig)
		return NULL;

	int rootfd = open(modconfig->docroot, O_PATH | O_DIRECTORY);
	if (rootfd == -1)
	{
		err("cgi: %s access denied", modconfig->docroot);
		return NULL;
	}

	mod = calloc(1, sizeof(*mod));
	mod->rootfd = rootfd;
	mod->config = modconfig;
	mod->server = server;

	httpserver_addconnector(server, _cgi_connector, mod, CONNECTOR_DOCUMENT, str_cgi);

	return mod;
}

static void mod_cgi_destroy(void *arg)
{
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;
	// nothing to do
	close(mod->rootfd);
	if (mod->config->env)
		free(mod->config->env);
	free(mod->config);
	free(mod);
}

static void _cgi_freectx(mod_cgi_ctx_t *ctx)
{
	if (ctx->chunk)
		free(ctx->chunk);
	if (ctx->fromcgi[0])
		close(ctx->fromcgi[0]);
	if (ctx->tocgi[1] > 0)
		close(ctx->tocgi[1]);
	free(ctx);
}

static int _mod_cgi_fork(mod_cgi_ctx_t *ctx, http_message_t *request, string_t *cgi_path, string_t *path_info)
{
	_mod_cgi_t *mod = ctx->mod;
	const mod_cgi_config_t *config = mod->config;

	if (pipe(ctx->tocgi) < 0)
		return EREJECT;
	if (pipe(ctx->fromcgi))
		return EREJECT;
	pid_t pid = fork();
	if (pid)
	{
		/* keep only input of the pipe */
		close(ctx->tocgi[0]);
		/* keep only output of the pipe */
		close(ctx->fromcgi[1]);
#ifdef DEBUG
		char **envs = NULL;
		envs = cgi_buildenv(config, request, cgi_path, path_info);
		char *env = *envs++;
		while (env != NULL)
		{
			free(env);
			env = *envs++;
		}
#endif
	}
	else /* into child */
	{
		int flags;
		flags = fcntl(ctx->tocgi[0],F_GETFD);
		fcntl(ctx->tocgi[0],F_SETFD, flags | FD_CLOEXEC);
		flags = fcntl(ctx->fromcgi[1],F_GETFD);
		fcntl(ctx->fromcgi[1],F_SETFD, flags | FD_CLOEXEC);
		/* send data from server to the stdin of the cgi */
		close(ctx->tocgi[1]);
		dup2(ctx->tocgi[0], STDIN_FILENO);
		close(ctx->tocgi[0]);
		/* send data from the stdout of the cgi to server */
		close(ctx->fromcgi[0]);
		dup2(ctx->fromcgi[1], STDOUT_FILENO);
		close(ctx->fromcgi[1]);

		int sock = httpmessage_keepalive(request);

		char * const argv[2] = { (char *)cgi_path->data, NULL };

		char **env = NULL;
		env = cgi_buildenv(config, request, cgi_path, path_info);

		close(sock);

		setlinebuf(stdout);
		sched_yield();
		/**
		 * cgipath is absolute, but in fact execveat runs in docroot.
		 */
#ifdef USE_EXECVEAT
		execveat(mod->rootfd, cgi_path->data, argv, env, 0);
#else
		// this part die if the program is running under valgrind
		// use execeat
		int scriptfd = openat(mod->rootfd, cgi_path->data, O_PATH);
		close(mod->rootfd);
		fexecve(scriptfd, argv, env);
#endif
		err("cgi error: %s", strerror(errno));
		exit(0);
	}
	return pid;
}

static int _cgi_changestate(mod_cgi_ctx_t *ctx, int state)
{
	if (state <= STATE_INMASK)
		state |= (ctx->state & STATE_OUTMASK);
	else
		state |= (ctx->state & STATE_INMASK);
	ctx->state = state;
	return state;
}

static int _cgi_start(_mod_cgi_t *mod, http_message_t *request)
{
	const mod_cgi_config_t *config = mod->config;
	int ret = EREJECT;
	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request,"uri", &uri);
	if (urilen > 0 && config->docroot)
	{
		const char *path_info = NULL;
		if (htaccess_check(&config->htaccess, uri, &path_info) != ESUCCESS)
		{
			dbg("cgi: %s forbidden extension", uri);
			return EREJECT;
		}

		while (*uri == '/' && *uri != '\0')
		{
			uri++;
			urilen--;
		}

		mod_cgi_ctx_t *ctx;
		ctx = calloc(1, sizeof(*ctx));
		char *data = calloc(1, urilen + 2);
		if (path_info != NULL)
		{
			/**
			 * split the URI between the CGI script path and the
			 * path_info for the CGI.
			 * /test.cgi/my/path_info => /test.cgi and  /my/path_info
			 */
			ctx->cgi_path.length = snprintf(data, urilen + 2, "%.*s", (int)(path_info - uri), uri);
			ctx->cgi_path.data = data;
			ctx->path_info.length = snprintf(data + ctx->cgi_path.length + 1, urilen - ctx->cgi_path.length + 1, "%s", path_info);
			ctx->path_info.data = data + ctx->cgi_path.length + 1;
		}
		else
		{
			ctx->cgi_path.length = snprintf(data, urilen + 2, "%s", uri);
			ctx->cgi_path.data = data;
		}

		/**
		 * check the path access
		 */
		int scriptfd = -1;
		scriptfd = openat(mod->rootfd, ctx->cgi_path.data, O_PATH);
		if (scriptfd < 0)
		{
			warn("cgi: %s error %s", ctx->cgi_path.data, strerror(errno));
			free(ctx);
			return EREJECT;
		}

		struct stat filestat = {0};
		fstat(scriptfd, &filestat);

		if (S_ISDIR(filestat.st_mode))
		{
			dbg("cgi: %s is directory", uri);
			close(scriptfd);
			free(ctx);
			return EREJECT;
		}
		/* at least user or group may execute the CGI */
		if ((filestat.st_mode & (S_IXUSR | S_IXGRP)) != (S_IXUSR | S_IXGRP))
		{
			warn("cgi: %s access denied", uri);
			warn("cgi: %s", strerror(errno));
			close(scriptfd);
			free(ctx);
			return ESUCCESS;
		}

		dbg("cgi: run %s", uri);
		ctx->mod = mod;
		ctx->pid = _mod_cgi_fork(ctx, request, &ctx->cgi_path, &ctx->path_info);
		ctx->state = STATE_INSTART;
		ctx->chunk = malloc(config->chunksize + 1);
		httpmessage_private(request, ctx);
		close(scriptfd);
		ret = EINCOMPLETE;
	}
	return ret;
}

static int _cgi_request(mod_cgi_ctx_t *ctx, http_message_t *request)
{
	_mod_cgi_t *mod = ctx->mod;
	int ret = ECONTINUE;
	const char *input = NULL;
	int inputlen;
	size_t rest;

	inputlen = httpmessage_content(request, &input, &rest);
	if (inputlen > 0)
	{
		int len;
#ifdef DEBUG
		static size_t length = 0;
		length += inputlen;
		cgi_dbg("cgi: %lu/%lu input %s", length, rest, input);
#endif
		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(ctx->tocgi[1], &wfds);

		ret = select(ctx->tocgi[1] + 1, NULL, &wfds, NULL, &mod->config->timeout);
		if (ret == 1)
			len = write(ctx->tocgi[1], input, inputlen);
		else
			len = 0;
		cgi_dbg("cgi: wrote %d %d", len, inputlen);
		if (inputlen != len)
		{
			//_cgi_changestate(ctx, STATE_INFINISH);
			ret = EREJECT;
		}
	}
	else if (inputlen != EINCOMPLETE)
		_cgi_changestate(ctx, STATE_INFINISH);
	return ret;
}

static int _cgi_parseresponse(mod_cgi_ctx_t *ctx, http_message_t *response, char * chunk, int rest)
{
	int ret;

	ret = httpmessage_parsecgi(response, chunk, &rest);
	cgi_dbg("cgi: parse %d data %d\n%s#", ret, rest, chunk);
	if (ret == ECONTINUE && (ctx->state & STATE_OUTMASK) < STATE_HEADERCOMPLETE)
	{
#if defined(RESULT_302)
		/**
		 * RFC 3875 : 6.2.3
		 */
		const char *location = httpmessage_REQUEST(response, str_location);
		if (location != NULL && location[0] != '\0')
			httpmessage_result(response, RESULT_302);
#endif
		_cgi_changestate(ctx, STATE_HEADERCOMPLETE);
	}
	if (ret == ESUCCESS)
	{
		_cgi_changestate(ctx, STATE_CONTENTCOMPLETE);
		//parse_cgi is complete but not this module
	}
	return ret;
}

static int _cgi_response(mod_cgi_ctx_t *ctx, http_message_t *response)
{
	_mod_cgi_t *mod = ctx->mod;
	const mod_cgi_config_t *config = mod->config;
	int ret = ECONTINUE;
	int sret;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(ctx->fromcgi[0], &rfds);
	sret = select(ctx->fromcgi[0] + 1, &rfds, NULL, NULL, &mod->config->timeout);
	if (sret > 0 && FD_ISSET(ctx->fromcgi[0], &rfds))
	{
		int size = config->chunksize;
		size = read(ctx->fromcgi[0], ctx->chunk, size);
		if (size < 0)
		{
			err("cgi: read %s", strerror(errno));
			_cgi_changestate(ctx, STATE_OUTFINISH);
		}
		else if (size < 1)
		{
			dbg("cgi: died");
			_cgi_changestate(ctx, STATE_OUTFINISH);
		}
		else
		{
			ctx->chunk[size] = 0;
			cgi_dbg("cgi: receive (%d)\n%s", size, ctx->chunk);
			/**
			 * if content_length is not null, parcgi is able to
			 * create the content.
			 * But the cgi know the length at the end, is too late
			 * to set the header.
			 */
			int rest = size;
			if (rest > 0)
			{
				ret = _cgi_parseresponse(ctx, response, ctx->chunk, rest);
			}
		}
	}
	else
	{
		_cgi_changestate(ctx, STATE_OUTFINISH);
		kill(ctx->pid, SIGTERM);
		dbg("cgi: complete");
		ret = ECONTINUE;
	}
	return ret;
}
static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EINCOMPLETE;
	mod_cgi_ctx_t *ctx = httpmessage_private(request, NULL);
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;

	if (ctx == NULL)
	{
		ret = _cgi_start(mod, request);
		if (ret == ESUCCESS)
			httpmessage_result(response, RESULT_403);
		if (ret != EINCOMPLETE)
			return ret;
		ctx = httpmessage_private(request, NULL);
		_cgi_request(ctx, request);
		_cgi_changestate(ctx, STATE_OUTSTART);
	}
	else
	{

		int instate = (ctx->state & STATE_INMASK);
		if (ctx->tocgi[1] > 0 && instate >= STATE_INSTART && instate < STATE_INFINISH)
		{
			_cgi_request(ctx, request);
			/**
			 * Read the request. The connector is still EINCOMPLETE
			 */
		}
		else if (instate == STATE_INFINISH)
		{
			if (ctx->tocgi[1] > 0)
				close(ctx->tocgi[1]);
			ctx->tocgi[1] = -1;
			_cgi_changestate(ctx, STATE_INMASK);
		}
		/**
		 * when the request is complete the module must check the CGI immedialty
		 * otherwise the client will wait more data from request
		 */
		int outstate = (ctx->state & STATE_OUTMASK);
		if (outstate >= STATE_OUTSTART && outstate < STATE_CONTENTCOMPLETE)
		{
			do
			{
				ret = _cgi_response(ctx, response);
			} while(ret == EINCOMPLETE);
			/**
			 * the request is completed to not wait more data the module
			 * must returns ECONTINUE or ESUCCESS now
			 */
			ret = ECONTINUE;
		}
		else if (outstate == STATE_CONTENTCOMPLETE)
		{
			ret = httpmessage_parsecgi(response, NULL, 0);
			ret = ECONTINUE;
			_cgi_changestate(ctx, STATE_OUTFINISH);
		}
		else if (outstate == STATE_OUTFINISH)
		{
			close(ctx->fromcgi[0]);
			if (instate == STATE_INMASK)
				ctx->state = STATE_END;
			ret = ECONTINUE;
		}
		else if (ctx->state == STATE_END)
		{
			_cgi_freectx(ctx);
			httpmessage_private(request, NULL);
			ret = ESUCCESS;
		}
	}
	/* this mod returns EINCOMPLETE
	 * because it needs to wait the end
	 * to know the length of the content */
	return ret;
}

const module_t mod_cgi =
{
	.version = 0x01,
	.name = str_cgi,
	.configure = (module_configure_t)&cgi_config,
	.create = (module_create_t)&mod_cgi_create,
	.destroy = &mod_cgi_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_cgi")));
#endif
