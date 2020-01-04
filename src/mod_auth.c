/*****************************************************************************
 * mod_auth.c: Authentication module
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
/**
    auth module needs the type of authentication ("Basic" or "Digest").
    After the rule to check the password is an authn_<type>_<name>
    sublibrary (just a C file).

    With this solution each server may has its own authentication type.
    After the checking of the password is done by a library linked to the
    mod_auth library.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_none.h"
#ifdef AUTHN_BASIC
#include "authn_basic.h"
#endif
#ifdef AUTHN_DIGEST
#include "authn_digest.h"
#endif
#ifdef AUTHN_BEARER
#include "authn_bearer.h"
#endif
#ifdef AUTHN_OAUTH2
#include "authn_oauth2.h"
#endif
#include "authz_simple.h"
#include "authz_file.h"
#include "authz_unix.h"
#include "authz_sqlite.h"
#include "authz_jwt.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define auth_dbg(...)

#ifndef RESULT_401
#error mod_auth require RESULT_401
#endif

typedef struct _mod_auth_s _mod_auth_t;
typedef struct _mod_auth_ctx_s _mod_auth_ctx_t;

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _home_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);
static char *authz_generatetoken(mod_auth_t *mod, authsession_t *info);

static const char str_auth[] = "auth";
static const char str_cachecontrol[] = "Cache-Control";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *ctl;
	char *authenticate;
	authsession_t *info;
};

struct _mod_auth_s
{
	mod_auth_t	*config;
	const char *type;
	authn_t *authn;
	authz_t *authz;
	int typelength;
};

const char str_authenticate[] = "WWW-Authenticate";
const char str_authorization[] = "Authorization";
const char str_anonymous[] = "anonymous";

static const char *str_xtoken = "X-Auth-Token";
static const char *str_xuser = "X-Remote-User";
static const char *str_xgroup = "X-Remote-Group";
static const char *str_xhome = "X-Remote-Home";
static const char *str_user = "USER";
static const char *str_group = "GROUP";
static const char *str_home = "HOME";
static const char *str_wilcard = "*";
const char *str_authenticate_types[] =
{
	"None",
	"Basic",
	"Digest",
	"Bearer",
	"oAuth2",
};
const char *str_authenticate_engine[] =
{
	"simple",
	"file",
	"unix",
	"sqlite",
	"jwt",
};
authn_rules_t *authn_rules[] = {
#ifdef AUTHN_NONE
	&authn_none_rules,
#else
	NULL,
#endif
#ifdef AUTHN_BASIC
	&authn_basic_rules,
#else
	NULL,
#endif
#ifdef AUTHN_DIGEST
	&authn_digest_rules,
#else
	NULL,
#endif
#ifdef AUTHN_BEARER
	&authn_bearer_rules,
#else
	NULL,
#endif
#ifdef AUTHN_OAUTH2
	&authn_oauth2_rules,
#else
	NULL,
#endif
};

authz_rules_t *authz_rules[] = {
	NULL,
#ifdef AUTHZ_SIMPLE
	&authz_simple_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_FILE
	&authz_file_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_UNIX
	&authz_unix_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_SQLITE
	&authz_sqlite_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_JWT
	&authz_jwt_rules,
#else
	NULL,
#endif
};

void *mod_auth_create(http_server_t *server, mod_auth_t *config)
{
	_mod_auth_t *mod;

	srandom(time(NULL));

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->authz = calloc(1, sizeof(*mod->authz));
	mod->authz->type = config->authz_type;

	mod->authz->rules = authz_rules[config->authz_type & AUTHZ_TYPE_MASK];
	if (mod->authz->rules == NULL)
	{
		err("authentication storage not set, change configuration");
		free(mod->authz);
		free(mod);
		return NULL;
	}

#ifdef AUTHZ_JWT
	/**
	 * jwt token contains user information
	 * it is useless to "join" the token to the user.
	 */
	mod->authz->generatetoken = authz_generatejwtoken;
#else
	if ((config->authz_type & AUTHZ_TOKEN_E) &&  (authz_rules[config->authz_type & AUTHZ_TYPE_MASK])->join == NULL)
	{
		err("Please use other authz module (sqlite) to enable token");
		config->authz_type &= ~AUTHZ_TOKEN_E;
	}
	else
		mod->authz->generatetoken = authz_generatetoken;
#endif

	mod->authz->ctx = mod->authz->rules->create(config->authz_config);
	if (mod->authz->ctx == NULL)
	{
		free(mod->authz);
		free(mod);
		return NULL;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->server = server;
	mod->authn->type = config->authn_type;
	mod->authn->rules = authn_rules[config->authn_type];
	if (mod->authn->rules == NULL)
		err("authentication type is not availlable, change configuration");

	if (config->algo)
	{
		if (hash_sha1 && !strcmp(config->algo, hash_sha1->name))
		{
			mod->authn->hash = hash_sha1;
		}
		else if (hash_sha224 && !strcmp(config->algo, hash_sha224->name))
		{
			mod->authn->hash = hash_sha224;
		}
		else if (hash_sha256 && !strcmp(config->algo, hash_sha256->name))
		{
			mod->authn->hash = hash_sha256;
		}
		else if (hash_sha512 && !strcmp(config->algo, hash_sha512->name))
		{
			mod->authn->hash = hash_sha512;
		}
		else
		{
			warn("auth: bad algorithm %s (%s | %s | %s | %s)",
				config->algo,
				(hash_sha1?hash_sha1->name:""),
				(hash_sha224?hash_sha224->name:""),
				(hash_sha256?hash_sha256->name:""),
				(hash_sha512?hash_sha512->name:""));
		}
	}
	if (mod->authn->hash == NULL && hash_md5)
	{
		mod->authn->hash = hash_md5;
	}
	if (mod->authn->rules && mod->authz->rules)
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authn, mod->authz, config->authn_config);
	}
	if (mod->authn->ctx)
	{
		mod->type = str_authenticate_types[config->authn_type];
		mod->typelength = strlen(mod->type);

		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod, str_auth);
	}
	else
	{
		if (mod->authn->rules && mod->authz->rules->destroy)
			mod->authz->rules->destroy(mod->authz->ctx);
		free(mod->authz);
		free(mod->authn);
		free(mod);
		mod = NULL;
	}

	if (mod != NULL && (!config->protect || config->protect[0] == '\0'))
	{
		config->protect = (char *)str_wilcard;
	}
	return mod;
}

void mod_auth_destroy(void *arg)
{
	_mod_auth_t *mod = (_mod_auth_t *)arg;
	if (mod->authn->ctx  && mod->authn->rules->destroy)
	{
		mod->authn->rules->destroy(mod->authn->ctx);
	}
	if (mod->authz->ctx && mod->authz->rules->destroy)
	{
		mod->authz->rules->destroy(mod->authz->ctx);
	}
	free(mod->authn);
	free(mod->authz);
	free(mod);
}

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_auth_t *mod = (_mod_auth_t *)arg;

	ctx->mod = mod;
	ctx->ctl = ctl;

	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(ctl, _home_connector, ctx, CONNECTOR_AUTH, str_auth);
	httpclient_addconnector(ctl, _authn_connector, ctx, CONNECTOR_AUTH, str_auth);
	/**
	 * authn may require prioritary connector and it has to be added after this one
	 */
	if(mod->authn->rules->setup)
		mod->authn->rules->setup(mod->authn->ctx, ctl, addr, addrsize);

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;
	if (ctx->info)
	{
		if (ctx->info->token)
			free(ctx->info->token);
		free(ctx->info);
	}
	free(ctx->authenticate);
	free(ctx);
}

static int _home_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	_mod_auth_t *mod = ctx->mod;
	int ret = EREJECT;
	const authsession_t *info = httpmessage_SESSION(request, str_auth, NULL);
	if (info)
	{
		const char *home = info->home;
		/**
		 * disable home redirection for websocket
		 */
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
		char *uri = utils_urldecode(httpmessage_REQUEST(request, "uri"));
		int homelength = strlen(home);
		if ((homelength > 0) &&
			(strncmp(home + 1, uri, homelength - 1) != 0))
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			char *location = calloc(1, homelength + 1 + 1);
			snprintf(location, homelength + 1 + 1, "%s/", home);
			httpmessage_addheader(response, str_location, location);
			httpmessage_result(response, RESULT_301);
			free(location);
			ret = ESUCCESS;
#endif
		}
		free(uri);
	}
	return ret;
}

static char *authz_generatetoken(mod_auth_t *mod, authsession_t *info)
{
	char *token = calloc(1, 36);
	char _nonce[24];
	int i;
	for (i = 0; i < 6; i++)
	{
		*(int *)(_nonce + i * 4) = random();
	}
	int ret = 0;
	ret = base64_urlencoding->encode(_nonce, 24, token, 36);
	return token;
}

static const char *_authn_getauthorization(_mod_auth_ctx_t *ctx, http_message_t *request)
{
	_mod_auth_t *mod = ctx->mod;
	const char *authorization = NULL;
	/**
	 * with standard authentication, the authorization code
	 * is sended info header
	 */
	if (authorization == NULL || authorization[0] == '\0')
	{
		authorization = httpmessage_REQUEST(request, (char *)str_authorization);
	}
	/**
	 * to send the authorization header only once, the "cookie"
	 * option of the server store the authorization inside cookie.
	 * This method allow to use little client which manage only cookie.
	 */
	if (authorization == NULL || authorization[0] == '\0')
	{
		authorization = cookie_get(request, (char *)str_authorization);
		err("cookie get %s %p",str_authorization, authorization);
	}

	if (authorization != NULL && strncmp(authorization, mod->type, mod->typelength))
	{
		err("authorization type: %.*s, %.*s", mod->typelength, authorization, mod->typelength, mod->type);
		authorization = NULL;
	}
#ifdef AUTH_TOKEN
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if ((authorization == NULL || authorization[0] == '\0') && mod->authz->type & AUTHZ_TOKEN_E)
	{
		if (mod->authz->type & AUTHZ_HEADER_E)
		{
			authorization = httpmessage_REQUEST(request, str_xtoken);
		}
		else
		{
			authorization = cookie_get(request, str_xtoken);
		}
	}
#endif
	return authorization;
}

typedef void (*_httpmessage_set)(http_message_t *, const char *, const char *);
static int _authn_setauthorization(_mod_auth_ctx_t *ctx, const char *authorization,
			authsession_t *info, _httpmessage_set httpmessage_set, http_message_t *response)
{
	_mod_auth_t *mod = ctx->mod;

#ifdef AUTH_TOKEN
	if (info->token)
	{
		httpmessage_set(response, str_xtoken, info->token);
	}
	else
#endif
	if (authorization != NULL)
		httpmessage_set(response, str_authorization, (char *)authorization);
	httpmessage_set(response, str_xuser, info->user);
	if (info->group)
		httpmessage_set(response, str_xgroup, info->group);
	if (info->home)
		httpmessage_set(response, str_xhome, "~/");
	return ESUCCESS;
}

static int _authn_checkauthorization(_mod_auth_ctx_t *ctx,
		const char *authorization,
		const char *method,
		const char *uri,
		http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	char *authentication = strchr(authorization, ' ');

	if (authentication)
		authentication++;
	else
		authentication = (char *)authorization;
	/**
	 * The current authentication is made by the client (the browser).
	 * In this case the client compute the autorization for each file to download.
	 * With redirection to the login page, all files should contain the code
	 * to compute the autorizarion. But it is impossible to do it. Then
	 * only the method HEAD is used to login and the client must send
	 * same autorization for all files to download.
	 * WARNING: It is incorrect to use this method for security.
	 * The autorization is always acceptable and it is dangerous.
	 */
	if (config->redirect)
		method = str_head;
	const char *user = mod->authn->rules->check(mod->authn->ctx, method, uri, authentication);
	if (user != NULL)
	{
		authsession_t *info = NULL;
		info = ctx->info;
		if (info == NULL)
		{
			const char *group = NULL;
			const char *home = NULL;
			info = calloc(1, sizeof(*info));
			strncpy(info->user, user, sizeof(info->user));
			strncpy(info->type, mod->type, sizeof(info->type));
#ifdef AUTH_TOKEN
			if (mod->authz->type & AUTHZ_TOKEN_E)
			{
				char *token = mod->authz->generatetoken(mod->config, info);
				if (mod->authz->rules->join)
					mod->authz->rules->join(mod->authz->ctx, info->user, token, mod->config->expire);
				info->token = token;
			}
#endif
			if (mod->authz->rules->group)
			{
				group = mod->authz->rules->group(mod->authz->ctx, user);
				if (group)
					strncpy(info->group, group, sizeof(info->group));
			}
			if (mod->authz->rules->home)
			{
				home = mod->authz->rules->home(mod->authz->ctx, user);
				if (home)
					strncpy(info->home, home, sizeof(info->home));
			}
			ctx->info = info;
		}
		if (mod->authz->type & AUTHZ_HEADER_E)
		{
			_authn_setauthorization(ctx, authorization, info, httpmessage_addheader, response);
		}
		else if (mod->authz->type & AUTHZ_COOKIE_E)
		{
			_authn_setauthorization(ctx, authorization, info, cookie_set, response);
		}

		if (mod->authz->type & AUTHZ_UNIX_E)
		{
			struct passwd *pw;
			pw = getpwnam(info->user);
			if (pw != NULL)
			{
				uid_t uid;
				uid = getuid();
				//only "saved set-uid", "uid" and "euid" may be set
				//first step: set the "saved set-uid" (root)
				if (seteuid(uid) < 0)
					warn("not enought rights to change user");
				//second step: set the new "euid"
				if (setegid(pw->pw_gid) < 0)
					warn("not enought rights to change group");
				if (seteuid(pw->pw_uid) < 0)
					warn("not enought rights to change user");
			}
		}
		warn("user \"%s\" accepted from %p", info->user, ctx->ctl);
		ret = EREJECT;
	}
	return ret;
}

static int _authn_challenge(_mod_auth_ctx_t *ctx, const char *uri,
				http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;

	ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	if (ret == ECONTINUE)
	{
		auth_dbg("auth challenge failed");
		const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
		if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL))
		{
			httpmessage_result(response, RESULT_403);
		}
		else if (config->redirect)
		{
			int protect = 1;
			/**
			 * check the url redirection
			 */
			const char *redirect = strstr(config->redirect, "://");
			if (redirect != NULL)
			{
				redirect += 3;
				redirect = strchr(redirect, '/');
			}
			else
				redirect = config->redirect;
			if (redirect[0] == '/')
				redirect++;
			protect = utils_searchexp(uri, redirect);
			if (protect == ESUCCESS)
			{
				/**
				 * the request URI is the URL of the redirection
				 * the authentication has to accept (this module
				 * reject to manage the request and another module
				 * should send response to the request0.
				 */
				httpmessage_result(response, RESULT_200);
				ret = EREJECT;
			}
			else
			{
				httpmessage_addheader(response, str_location, config->redirect);
				httpmessage_addheader(response, str_cachecontrol, "no-cache");
				httpmessage_result(response, RESULT_302);
			}
		}
		else
		{
			httpmessage_result(response, RESULT_401);
		}
		ret = ESUCCESS;
	}
	return ret;
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *authorization = NULL;
	const char *uriencoded;
	char *uri;

	/**
	 * If ctx->info is set, this connection has been already authenticated.
	 * It is useless to authenticate again.
	 */
	if (ctx->info != NULL)
	{
		if (mod->authz->type & AUTHZ_HEADER_E)
			_authn_setauthorization(ctx, NULL, ctx->info, httpmessage_addheader, response);
		else if (mod->authz->type & AUTHZ_COOKIE_E)
			_authn_setauthorization(ctx, NULL, ctx->info, cookie_set, response);
		return EREJECT;
	}

	uriencoded = httpmessage_REQUEST(request, "uri");
	uri = utils_urldecode(uriencoded);

	/**
	 * The header WWW-Authenticate inside the request
	 * allows to disconnect the user.
	 */
	authorization = httpmessage_REQUEST(request, (char *)str_authenticate);
	if (authorization != NULL && authorization[0] != '\0')
	{
		ret = ESUCCESS;
	}

	if (ret == ECONTINUE)
	{
		authorization = _authn_getauthorization(ctx, request);
		if (mod->authn->ctx && authorization != NULL)
		{
			ret = _authn_checkauthorization( ctx, authorization,
				httpmessage_REQUEST(request, "method"), uriencoded, response);
		}
	}

	if (ret == EREJECT)
	{
		/**
		 * authorization is good
		 */
		httpmessage_SESSION(request, str_auth, ctx->info);
	}
	else
	{
		int protect = 1;
		/**
		 * check uri
		 */
		protect = utils_searchexp(uri, config->protect);
		if (protect != ESUCCESS)
		{
			ret = EREJECT;
		}
		else
		{
			protect = utils_searchexp(uri, config->unprotect);
			if (protect == ESUCCESS)
			{
				ret = EREJECT;
			}
		}
	}


	if (ret != EREJECT)
	{
		ret = _authn_challenge(ctx, uri, request, response);
	}
	free(uri);
	return ret;
}

const module_t mod_auth =
{
	.name = str_auth,
	.create = (module_create_t)mod_auth_create,
	.destroy = mod_auth_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_auth")));
#endif
