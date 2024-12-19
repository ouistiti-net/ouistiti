/*****************************************************************************
 * mod_webstream.c: webstream server module
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
#include <sched.h>
#include <time.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_document.h"
#include "mod_webstream.h"

extern int ouistiti_websocket_run(void *arg, int sock, int wssock, http_client_t *clt);

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define webstream_dbg(...)

#define WEBSTREAM_REALTIME        0x01
#define WEBSTREAM_TLS             0x02
#define WEBSTREAM_MULTIPART       0x04
#define WEBSTREAM_MULTIPART_DATE  0x08

#define WEBSTREAM_DEFAULT_WAITTIME 34000

typedef struct mod_webstream_s mod_webstream_t;
struct mod_webstream_s
{
	string_t docroot;
	htaccess_t htaccess;
	int options;
	int fps;
};

typedef struct _mod_webstream_s _mod_webstream_t;
typedef struct _mod_webstream_ctx_s _mod_webstream_ctx_t;

typedef int (*socket_t)(mod_webstream_t *config, char *filepath);

struct _mod_webstream_s
{
	mod_webstream_t *config;
	socket_t socket;
	int fdroot;
};

struct _mod_webstream_ctx_s
{
	_mod_webstream_t *mod;
	char *protocol;
	int socket;
	int client;
	pid_t pid;
	http_client_t *clt;
	const char *mime;
	char *boundary;
};

static int _webstream_run(_mod_webstream_ctx_t *ctx, const http_message_t *request);

static const char str_webstream[] = "webstream";

static int _webstream_socket(_mod_webstream_ctx_t *ctx, int sock, const char *filepath)
{
	_mod_webstream_t *mod = ctx->mod;
	const mod_webstream_t *config = mod->config;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", filepath);

	if (config->options & WEBSTREAM_MULTIPART)
	{
		warn("webstream: multipart socket");
		sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	}
	else
	{
		warn("webstream: stream socket");
		sock = socket(AF_UNIX, SOCK_STREAM, 0);
	}
	if (sock > 0)
	{
		int ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0)
		{
			close(sock);
			sock = -1;
		}
	}
	if (sock == -1)
	{
		err("webstream: %s error: %s", filepath, strerror(errno));
	}
	return sock;
}

char *mkrndstr(size_t length)
{
	static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
	char *randomString = NULL;

	if (length)
	{
		randomString = malloc(length +1);

		if (randomString)
		{
			int l = (int) (sizeof(charset) -1);
			int key;
			for (int n = 0;n < length;n++)
			{
				key = random() % l;
				randomString[n] = charset[key];
			}
			randomString[length] = '\0';
		}
	}

	return randomString;
}

static int _webstream_start(_mod_webstream_ctx_t *ctx, const mod_webstream_t *config, http_message_t *response, const char *uri)
{
	ctx->socket = httpmessage_lock(response);
	ctx->mime = utils_getmime(uri);
	if (config->options & WEBSTREAM_MULTIPART)
	{
		ctx->boundary = mkrndstr(16);
		char mime[256];
		mime[255] = 0;
		snprintf(mime, 255, "%s; boundary=%s", str_multipart_replace, ctx->boundary);
		httpmessage_addcontent(response, mime, NULL, -1);
	}
	else
		httpmessage_addcontent(response, ctx->mime, NULL, -1);

	if (fchdir(ctx->mod->fdroot) == -1)
		warn("webstream: impossible to change directory");
	int wssock;
	wssock = _webstream_socket(ctx, ctx->socket, uri);
#ifdef WEBSOCKET_RT
	if (config->options & WEBSTREAM_REALTIME)
	{
		if (ouistiti_websocket_run(ctx, ctx->socket, wssock, httpmessage_client(response)) == ESUCCESS)
			wssock = 0;
	}
#endif
	return wssock;
}

static int _webstream_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;
	_mod_webstream_t *mod = ctx->mod;
	const mod_webstream_t *config = mod->config;

	if (ctx->client == 0)
	{
		/// first call of the conenctor
		const char *path_info = NULL;
		const char *uri = httpmessage_REQUEST(request, "uri");
		if (htaccess_check(&mod->config->htaccess, uri, &path_info) != ESUCCESS)
		{
			dbg("webstream: %s forbidden", uri);
			return EREJECT;
		}

		while (*uri == '/' && *uri != '\0') uri++;
		int fdfile = openat(mod->fdroot, uri, O_PATH);
		if (fdfile == -1)
		{
			return EREJECT;
		}
		struct stat filestat;
		fstat(fdfile, &filestat);
		close(fdfile);

		if ((S_ISSOCK(filestat.st_mode)) &&
			((ctx->client = _webstream_start(ctx, config, response, uri)) > 0))
		{
			ctx->socket = httpmessage_lock(response);
			warn("webstream: connect to %s", uri);
			ret = ECONTINUE;
		}
		else
		{
			httpmessage_result(response, RESULT_400);
			ret = ESUCCESS;
		}
	}
	else
	{
		if (!(config->options & WEBSTREAM_REALTIME))
		{
			ctx->pid = _webstream_run(ctx, request);
		}
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_webstream_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	_mod_webstream_t *mod = (_mod_webstream_t *)arg;
	_mod_webstream_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	ctx->clt = clt;
	httpclient_addconnector(clt, _webstream_connector, ctx, CONNECTOR_DOCUMENT, str_webstream);

	return ctx;
}

static void _mod_webstream_freectx(void *arg)
{
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;

	if (ctx->pid > 0)
	{
#ifdef VTHREAD
		dbg("webstream: waitpid");
		waitpid(ctx->pid, NULL, 0);
		warn("webstream: end stream %p", ctx->clt);
#else
		/**
		 * ignore SIGCHLD allows the child to die without to create a z$
		 */
		struct sigaction action;
		action.sa_flags = SA_SIGINFO;
		sigemptyset(&action.sa_mask);
		action.sa_handler = SIG_IGN;
		sigaction(SIGCHLD, &action, NULL);
#endif
		shutdown(ctx->client, SHUT_RD);
		close(ctx->client);
		httpclient_shutdown(ctx->clt);
		if (ctx->boundary)
			free(ctx->boundary);
	}
	free(ctx);
}

#ifdef FILE_CONFIG

static int webstream_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int conf_ret = ESUCCESS;
	mod_webstream_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "webstream");
#else
	config_setting_t *config = config_setting_lookup(iterator, "webstream");
#endif
	if (config && config_setting_is_list(config))
	{
			if (index >= config_setting_length(config))
				return EREJECT;
			config = config_setting_get_elem(config, index);
			conf_ret = ECONTINUE;
	}
	if (config)
	{
		const char *string = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(config, "docroot", &string);
		string_store(&conf->docroot, string, -1);
		htaccess_config(config, &conf->htaccess);
		config_setting_lookup_int(config, "fps", &conf->fps);
		config_setting_lookup_string(config, "options", &string);
		if (utils_searchexp("direct", string, NULL) == ESUCCESS && ouistiti_issecure(server))
			conf->options |= WEBSTREAM_REALTIME;
		if (utils_searchexp("multipart", string, NULL) == ESUCCESS)
			conf->options |= WEBSTREAM_MULTIPART;
		if (utils_searchexp("date", string, NULL) == ESUCCESS)
			conf->options |= WEBSTREAM_MULTIPART_DATE;
	}
	else
		conf_ret = EREJECT;
	*modconfig = (void*)conf;
	return conf_ret;
}
#else
static const mod_webstream_t g_webstream_config =
{
	.docroot = STRING_DCL(DATADIR"/webstream"),
};

static void *webstream_config(void *iterator, server_t *server)
{
	return (void *)&g_webstream_config;
}
#endif

static void *mod_webstream_create(http_server_t *server, mod_webstream_t *config)
{
	if (config == NULL)
		return NULL;

	int fdroot = open(string_toc(&config->docroot), O_DIRECTORY);
	if (fdroot == -1)
	{
		err("webstream: docroot %s not found", config->docroot.data);
		return NULL;
	}

	_mod_webstream_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->fdroot = fdroot;
	httpserver_addmod(server, _mod_webstream_getctx, _mod_webstream_freectx, mod, str_webstream);
	srandom(time(NULL));
	return mod;
}

static void mod_webstream_destroy(void *data)
{
	_mod_webstream_t *mod = (_mod_webstream_t *)data;
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	close(mod->fdroot);
	free(data);
}

typedef struct _webstream_main_s _webstream_main_t;
struct _webstream_main_s
{
	_mod_webstream_ctx_t *modctx;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
};

static int _webstream_sendpartheader(_webstream_main_t *info, size_t length, int date)
{
	char buffer[256] = {0};
	int ret;
	ret = snprintf(buffer, 255, "\r\n--%s\r\n", info->modctx->boundary);
	if (ret > 0)
		info->sendresp(info->ctx, buffer, ret);
	ret = snprintf(buffer, 255, "%s: %s\r\n", str_contenttype, info->modctx->mime);
	if (ret > 0)
		info->sendresp(info->ctx, buffer, ret);
	ret = snprintf(buffer, 255, "%s: %lu\r\n", str_contentlength, length);
	if (ret > 0)
		info->sendresp(info->ctx, buffer, ret);

	if (date)
	{
		time_t t;
		struct tm *tmp, tmp_r;

		t = time(NULL);
		tmp = gmtime_r(&t, &tmp_r);
		char buf[26];
		asctime_r(&tmp_r, buf);
		ret = snprintf(buffer, 255, "%s: %s\r\n", str_date, buf);
		if (ret > 0)
			info->sendresp(info->ctx, buffer, ret);
	}
	if (info->sendresp(info->ctx, "\r\n", 2) != 2)
	{
		err("webstream: send error %s", strerror(errno));
		return EREJECT;
	}
	return ESUCCESS;
}

static int _webstream_transferdata(_webstream_main_t *info, int multipart)
{
	int end = 0;
	int client = info->modctx->client;
	int length;
	ioctl(client, FIONREAD, &length);
	if ((length == 0) ||
		(multipart && _webstream_sendpartheader(info, length, multipart & WEBSTREAM_MULTIPART_DATE) != ESUCCESS))
	{
		end = 1;
	}
	while (length > 0)
	{
		char *buffer;
		buffer = calloc(1, length);
		ssize_t ret = recv(client, buffer, length, MSG_NOSIGNAL);
		if (ret <= 0)
		{
			err("webstream: end stream %s", strerror(errno));
			free(buffer);
			end = 1;
			break;
		}
		/// ret is always <= length
		length -= ret;
		ssize_t size = 0;
		while (size < ret)
		{
			int outlength = 0;
			outlength = info->sendresp(info->ctx, buffer, ret);
			if (outlength == EINCOMPLETE)
				continue;
			if (outlength == EREJECT)
			{
				err("webstream: send error %s", strerror(errno));
				end = 1;
				break;
			}
			size += outlength;
		}
		free(buffer);
	}
	return end;
}

static void *_webstream_main(void *arg)
{
	_webstream_main_t *info = (_webstream_main_t *)arg;
	_mod_webstream_t *mod = info->modctx->mod;
	const mod_webstream_t *config = mod->config;
	int client = info->modctx->client;
	int socket = info->modctx->socket;
	int end = 0;
	struct timespec waittime = { .tv_sec = 0, .tv_nsec = (WEBSTREAM_DEFAULT_WAITTIME * 1000),};
	if (mod->config->fps > 0)
		waittime.tv_nsec = 1000000000 / mod->config->fps;

	while (!end)
	{
		fd_set rdfs;
		int maxfd = (client > socket)? client:socket;
		FD_ZERO(&rdfs);
		FD_SET(client, &rdfs);
		FD_SET(socket, &rdfs);
		int ret = select(maxfd + 1, &rdfs, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(socket, &rdfs))
		{
			/// no data should arrive from webclient,
			/// the event comes from the socket closing
			end = 1;
			ret--;
		}
		if ((ret > 0) && (FD_ISSET(client, &rdfs)))
		{
			end = _webstream_transferdata(info, config->options & (WEBSTREAM_MULTIPART | WEBSTREAM_MULTIPART_DATE));
			if (config->options & WEBSTREAM_MULTIPART)
			{
				nanosleep(&waittime, NULL);
			}
			ret--;
		}
		else if (errno != EAGAIN)
		{
			end = 1;
		}
	}
	close(client);
	return 0;
}

static int _webstream_run(_mod_webstream_ctx_t *ctx, const http_message_t *UNUSED(request))
{
	pid_t pid;
	_webstream_main_t info = {.modctx = ctx};
	info.ctx = httpclient_context(ctx->clt);
	info.recvreq = httpclient_addreceiver(ctx->clt, NULL, NULL);
	info.sendresp = httpclient_addsender(ctx->clt, NULL, NULL);

	if ((pid = fork()) == 0)
	{
		_webstream_main(&info);
		warn("websocket: process died");
		exit(0);
	}
	close(ctx->client);
	return pid;
}

const module_t mod_webstream =
{
	.version = 0x01,
	.name = str_webstream,
	.configure = (module_configure_t)&webstream_config,
	.create = (module_create_t)&mod_webstream_create,
	.destroy = &mod_webstream_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_webstream")));
#endif
