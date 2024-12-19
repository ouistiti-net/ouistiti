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

    https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_cookie.h"
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
#ifdef AUTHN_WWWFORM
#include "authn_wwwform.h"
#endif
#include "authz_simple.h"
#include "authz_file.h"
#include "authz_unix.h"
#include "authz_sqlite.h"
#include "authz_jwt.h"
#include "authz_totp.h"

#define auth_dbg(...)

#ifndef RESULT_401
#error mod_auth require RESULT_401
#endif
#ifndef RESULT_403
#error mod_auth require RESULT_403
#endif

#ifdef DEBUG
#warning "debug mode in unsafe"
#endif

typedef struct _mod_auth_s _mod_auth_t;
typedef struct _mod_auth_ctx_s _mod_auth_ctx_t;

static void *_mod_auth_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _home_connector(void *arg, http_message_t *request, http_message_t *response);
static int _forbidden_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);
#ifdef AUTH_TOKEN
static size_t _mod_auth_generatetoken(void *arg, http_message_t *UNUSED(request), char **token);
#endif

static const char str_auth[] = "auth";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *clt;
	char *authenticate;
	authn_t authn;
};

struct _mod_auth_s
{
	mod_auth_t	*config;
	string_t type;
	authn_t *authn;
	authz_t *authz;
	authz_rule_generatetoken_t generatetoken;
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
#ifdef AUTHN_WWWFORM
	&authn_wwwform_rules,
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
#ifdef AUTHZ_TOTP
	&authz_totp_rules,
#else
	NULL,
#endif
};

static const hash_t *_mod_findhash(const char *name, int nameid)
{
	const hash_t *hash_list[] =
	{
		hash_md5,
		hash_sha1,
		hash_sha224,
		hash_sha256,
		hash_sha512,
		hash_macsha256,
		NULL
	};

	static const hash_t *hash = NULL;
	for (int i = 0; i < (sizeof(hash_list) / sizeof(*hash_list)); i++)
	{
		hash = hash_list[i];
		if (hash != NULL &&
			((name != NULL && !strcasecmp(name, hash->name)) ||
				(nameid == hash->nameid)))
			break;
	}
	return hash;
}

static int _mod_sethash(mod_authn_t *config, const char *algo)
{
	int ret = EREJECT;
	if (algo)
	{
		config->hash = _mod_findhash(algo, -1);
	}
	if (config->hash != NULL)
	{
		ret = ESUCCESS;
	}
	else if (config->hash == NULL && hash_sha256)
	{
		config->hash = hash_sha256;
		ret = ESUCCESS;
	}

	if (ret == EREJECT && algo)
	{
		warn("auth: bad algorithm %s (%s | %s | %s | %s | %s)",
			algo,
			(hash_sha1?hash_sha1->name:""),
			(hash_sha224?hash_sha224->name:""),
			(hash_sha256?hash_sha256->name:""),
			(hash_sha512?hash_sha512->name:""),
			(hash_macsha256?hash_macsha256->name:""));
	}

	return ret;
}

#ifdef FILE_CONFIG
struct _authn_s
{
	void *(*config)(const config_setting_t *);
	authn_type_t type;
	string_t name;
};

struct _authn_s *authn_list[] =
{
#ifdef AUTHN_BASIC
	&(struct _authn_s){
		.config = &authn_basic_config,
		.type = AUTHN_BASIC_E,
		.name = STRING_DCL("Basic"),
	},
#endif
#ifdef AUTHN_DIGEST
	&(struct _authn_s){
		.config = &authn_digest_config,
		.type = AUTHN_DIGEST_E,
		.name = STRING_DCL("Digest"),
	},
#endif
#ifdef AUTHN_BEARER
	&(struct _authn_s){
		.config = &authn_bearer_config,
		.type = AUTHN_BEARER_E | AUTHN_REDIRECT_E | AUTHN_TOKEN_E,
		.name = STRING_DCL("Bearer"),
	},
#endif
#ifdef AUTHN_OAUTH2
	&(struct _authn_s){
		.config = &authn_oauth2_config,
		.type = AUTHN_OAUTH2_E | AUTHN_REDIRECT_E | AUTHN_TOKEN_E,
		.name = STRING_DCL("oAuth2"),
	},
#endif
#ifdef AUTHN_NONE
	&(struct _authn_s){
		.config = &authn_none_config,
		.type = AUTHN_NONE_E,
		.name = STRING_DCL("None"),
	},
#endif
#ifdef AUTHN_WWWFORM
	&(struct _authn_s){
		.config = &authn_wwwform_config,
		.type = AUTHN_WWWFORM_E,
		.name = STRING_DCL("wwwform"),
	},
#endif
};

static int authn_config(const config_setting_t *configauth, mod_authn_t *mod)
{
	int ret = EREJECT;

	char *type = NULL;
	if (config_setting_lookup_string(configauth, "type", (const char **)&type) != CONFIG_TRUE)
	{
		err("auth: authn type is not set");
		return ret;
	}

	const struct _authn_s *authn = NULL;
	for (int i = 0; i < (sizeof(authn_list) / sizeof(*authn_list)); i++)
	{
		if (!string_cmp(&authn_list[i]->name, type, -1))
			mod->config = authn_list[i]->config(configauth);
		if (mod->config != NULL)
		{
			authn = authn_list[i];
			break;
		}
	}

	if (authn != NULL)
	{
		mod->type |= authn->type;
		string_store(&mod->name, authn->name.data, authn->name.length);

		/**
		 * algorithm allow to change secret algorithm used during authentication default is md5. (see authn_digest.c)
		 */
		const char *algo = NULL;
		config_setting_lookup_string(configauth, "algorithm", &algo);
		_mod_sethash(mod, algo);

		ret = ESUCCESS;
	}
	else
		err("auth: authn '%s' not found", type);
	return ret;
}


struct _authz_s
{
	void *(*config)(const config_setting_t *);
	authz_type_t type;
	string_t name;
};

struct _authz_s *authz_list[] =
{
#ifdef AUTHZ_UNIX
	&(struct _authz_s){
		.config = &authz_unix_config,
		.type = AUTHZ_UNIX_E,
		.name = STRING_DCL("unix"),
	},
#endif
#ifdef AUTHZ_FILE
	&(struct _authz_s){
		.config = &authz_file_config,
		.type = AUTHZ_FILE_E,
		.name = STRING_DCL("file"),
	},
#endif
#ifdef AUTHZ_SQLITE
	&(struct _authz_s){
		.config = &authz_sqlite_config,
		.type = AUTHZ_SQLITE_E,
		.name = STRING_DCL("sqlite"),
	},
#endif
#ifdef AUTHZ_SIMPLE
	&(struct _authz_s){
		.config = &authz_simple_config,
		.type = AUTHZ_SIMPLE_E,
		.name = STRING_DCL("simple"),
	},
#endif
#ifdef AUTHZ_JWT
	&(struct _authz_s){
		.config = &authz_jwt_config,
		.type = AUTHZ_JWT_E,
		.name = STRING_DCL("jwt"),
	},
#endif
#ifdef AUTHZ_TOTP
	&(struct _authz_s){
		.config = &authz_totp_config,
		.type = AUTHZ_TOTP_E,
		.name = STRING_DCL("totp"),
	},
#endif
};

static void authz_optionscb(void *arg, const char *option)
{
	mod_auth_t *auth = (mod_auth_t *)arg;

	if (utils_searchexp("home", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_HOME_E;
	if (utils_searchexp("token", option, NULL) == ESUCCESS)
	{
		auth->authz.type |= AUTHZ_TOKEN_E;
		auth->token.type = E_OUITOKEN;
	}
	if (utils_searchexp("jwt", option, NULL) == ESUCCESS)
	{
		auth->authz.type |= AUTHZ_TOKEN_E;
		auth->token.type = E_JWT;
	}
	if (utils_searchexp("chown", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_CHOWN_E;

	if (utils_searchexp("cookie", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_COOKIE_E;
	if (utils_searchexp("header", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_HEADER_E;
	if (utils_searchexp("redirect", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_REDIRECT_E;
}

static int authz_config(const config_setting_t *configauth, mod_authz_t *mod)
{
	int ret = EREJECT;
	const struct _authz_s *authz = NULL;
	const char *name = NULL;
	ret = config_setting_lookup_string(configauth, "authz", &name);
	if (ret == CONFIG_FALSE)
		name = NULL;
	for (int i = 0; i < (sizeof(authz_list) / sizeof(*authz_list)); i++)
	{
		if (name != NULL)
		{
			if (! string_cmp(&authz_list[i]->name, name, -1))
				mod->config = authz_list[i]->config(configauth);
		}
		else if (authz_list[i]->config != NULL)
			mod->config = authz_list[i]->config(configauth);
		if (mod->config != NULL)
		{
			authz = authz_list[i];
			break;
		}
	}
	if (authz != NULL)
	{
		mod->type |= authz->type;
		string_store(&mod->name, authz->name.data, authz->name.length);
		ret = ESUCCESS;
	}
	return ret;
}

static mod_auth_t *_auth_config(const config_setting_t *config, server_t *server, const char *hostname)
{
	mod_auth_t *auth = NULL;
	int ret = ESUCCESS;
	auth = calloc(1, sizeof(*auth));
	/**
	 * signin URI allowed to access to the signin page
	 */
	const char *data = NULL;
	ret = config_setting_lookup_string(config, "signin", &data);
	if (ret == CONFIG_FALSE)
		ret = config_setting_lookup_string(config, "token_ep", &data);
	if (ret != CONFIG_FALSE)
		string_store(&auth->redirect, data, -1);
	ret = config_setting_lookup_string(config, "token_ep", &data);
	if (ret != CONFIG_FALSE)
		string_store(&auth->token_ep, data, -1);

	config_setting_lookup_string(config, "protect", &auth->protect);
	config_setting_lookup_string(config, "unprotect", &auth->unprotect);

	/**
	 * secret is the secret used during the token generation. (see authz_jwt.c)
	 */
	if (config_setting_lookup_string(config, "secret", &data) != CONFIG_FALSE)
		string_store(&auth->token.secret, data, -1);
	const char *mode = NULL;
	config_setting_lookup_string(config, "options", &mode);
	if (ouistiti_issecure(server))
		auth->authz.type |= AUTHZ_TLS_E;
	if (mode != NULL)
	{
		authz_optionscb(auth, mode);
	}
	if (config_setting_lookup_int(config, "expire", &auth->token.expire) == CONFIG_FALSE)
		auth->token.expire = 30;

	if (config_setting_lookup_string(config, "realm", &data) == CONFIG_FALSE)
		string_store(&auth->realm, hostname, -1);
	else
		string_store(&auth->realm, data, -1);

	ret = authz_config(config, &auth->authz);
	if (ret == EREJECT)
	{
		err("config: authz is not set");
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}
	if (auth->authz.type & AUTHZ_JWT_E)
		auth->token.type = E_JWT;
	if (config_setting_lookup_string(config, str_issuer, &data) == CONFIG_FALSE)
		string_store(&auth->token.issuer, STRING_INFO(auth->authz.name));
	else
		string_store(&auth->token.issuer, data, -1);

	ret = authn_config(config, &auth->authn);
	if (ret == EREJECT)
	{
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}

	if (auth->token.secret.data == NULL && auth->authz.type & AUTHZ_TOKEN_E)
	{
		err("auth: to enable the token, set the \"secret\" into configuration");
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}
	return auth;
}

static int auth_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int conf_ret = ESUCCESS;
	mod_auth_t *auth = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *config = config_setting_get_member(iterator, "auth");
#else
	const config_setting_t *config = config_setting_lookup(iterator, "auth");
#endif
	const char *hostname = NULL;
	if (config_setting_lookup_string(iterator, "hostname", &hostname) == CONFIG_FALSE)
		hostname = str_servername;
	if (config && config_setting_is_list(config))
	{
			if (index >= config_setting_length(config))
				return EREJECT;
			config = config_setting_get_elem(config, index);
			conf_ret = ECONTINUE;
	}
	if (config)
	{
		auth = _auth_config(config, server, hostname);
	}
	else
		conf_ret = EREJECT;
	*modconfig = (void *)auth;
	return conf_ret;
}
#else
static const mod_auth_t g_auth_config =
{
	.authz = &(mod_authz_t){
		.config = &(authz_sqlite_config_t){
			.dbname = "/etc/ouistiti/auth.db",
		},
		.type = AUTHZ_SQLITE_E,
		.name = "sqlite",
	},
	.authn = &(mod_authn_t){
		.type = AUTHN_BASIC_E,
		.name = "Basic",
	},
	.realm = NULL,
};

static int auth_config(void *iterator, server_t *server, int index, void **config)
{
	*config = (void *)&g_auth_config;
	return ESUCCESS;
}
#endif

static void *mod_auth_create(http_server_t *server, mod_auth_t *config)
{
	_mod_auth_t *mod;

	srandom(time(NULL));

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->authz = calloc(1, sizeof(*mod->authz));
	mod->authz->type = config->authz.type;
	string_store(&mod->authz->name,config->authz.name.data,config->authz.name.length);

	mod->authz->rules = authz_rules[config->authz.type & AUTHZ_TYPE_MASK];
	if (mod->authz->rules == NULL)
	{
		err("auth: storage not set, change configuration");
		free(mod->authz);
		free(mod);
		return NULL;
	}
	if (config->token.type == E_OUITOKEN)
		mod->generatetoken = &_mod_auth_generatetoken;
	else if (config->token.type == E_JWT)
		mod->generatetoken = &authz_jwt_generatetoken;

	mod->authz->ctx = mod->authz->rules->create(server, config->authz.config);
	if (mod->authz->ctx == NULL)
	{
		err("auth: authz %s not supported", string_toc(&mod->authz->name));
		free(mod->authz);
		free(mod);
		return NULL;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->config = config;
	if (config->authn.type != AUTHN_FORBIDDEN_E)
	{
		mod->authn->server = server;
		mod->authn->type = config->authn.type;
		mod->authn->rules = authn_rules[config->authn.type & AUTHN_TYPE_MASK];
	}
	if (mod->authn->rules == NULL)
		err("authentication type is not availlable, change configuration");
	else
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authn, config->authn.config);
	}
	if (mod->authn->ctx)
	{
		string_store(&mod->type, config->authn.name.data, config->authn.name.length);
		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod, str_auth);
	}
	else
	{
		httpserver_addconnector(server, _forbidden_connector, mod, CONNECTOR_AUTH, str_auth);
	}

	return mod;
}

static void mod_auth_destroy(void *arg)
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
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	free(mod);
}

static void *_mod_auth_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	_mod_auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_auth_t *mod = (_mod_auth_t *)arg;

	ctx->mod = mod;
	ctx->clt = clt;

	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(clt, _home_connector, ctx, CONNECTOR_AUTH, str_auth);
	httpclient_addconnector(clt, _authn_connector, ctx, CONNECTOR_AUTH, str_auth);
	/**
	 * authn may require prioritary connector and it has to be added after this one
	 */
	if(mod->authn->ctx && mod->authn->rules->setup)
	{
		ctx->authn.ctx = mod->authn->rules->setup(mod->authn->ctx, clt, addr, addrsize);
		ctx->authn.rules = mod->authn->rules;
	}

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;

	if(ctx->authn.ctx && ctx->authn.rules->cleanup)
		ctx->authn.rules->cleanup(ctx->authn.ctx);
	free(ctx->authenticate);
	free(ctx);
}

static int _forbidden_connector(void *UNUSED(arg), http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	err("auth: configuration error, all access are lock");
	httpmessage_result(response, RESULT_401);
	return ret;
}

static int _home_connector(void *UNUSED(arg), http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const char *home = NULL;
	size_t homelength = auth_info2(request, "home", &home);

	if (home)
	{
		/**
		 * disable home redirection for websocket
		 */
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
		const char *uri = httpmessage_REQUEST(request, "uri");

		if ((homelength > 0) && !strncmp(home + 1, uri, homelength - 1))
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			httpmessage_addheader(response, str_location, home, homelength);
			httpmessage_appendheader(response, str_location, STRING_REF("/"));
			httpmessage_result(response, RESULT_301);
			ret = ESUCCESS;
#endif
		}
	}
	return ret;
}

static int _authz_computepasswd(const hash_t *hash, const string_t *user,
			const string_t *realm, const string_t *passwd,
			char *string, int stringlen)
{
	char hashpasswd[32];
	void *ctx;

	ctx = hash->init();
	if (realm)
	{
		hash->update(ctx, user->data, user->length);
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm->data, realm->length);
		hash->update(ctx, ":", 1);
	}
	hash->update(ctx, passwd->data, passwd->length);
	hash->finish(ctx, hashpasswd);

	int length = base64->encode(hashpasswd, hash->size, string, stringlen);
	return length;
}

int authz_checkpasswd(const char *checkpasswd,  const string_t *user,
		const string_t *realm, const string_t *passwd)
{
	int ret = EREJECT;
	auth_dbg("auth: %s check %s %s", user->data, passwd->data, checkpasswd);
	if (checkpasswd[0] == '$')
	{
		const hash_t *hash = NULL;
		char hashtype = checkpasswd[1];
		if (checkpasswd[1] == 'a')
		{
			hashtype = checkpasswd[2];
		}
		const char *checkrealm = NULL;
		int checkrealmlen = 0;
		/**
		 * If the realm is linked to the password,
		 * it must be the same as the requested realm.
		 * If no realm is available with the password,
		 * we check directly the password
		 */
		checkrealm = strstr(checkpasswd, "realm=");
		if (checkrealm)
		{
			checkrealm += 6;
			checkrealmlen = strpbrk(checkrealm, ";$") - checkrealm - 1;
			if (string_empty(realm) || string_cmp(realm, checkrealm, checkrealmlen))
				return ret;
		}
		else
			realm = NULL;

		hash = _mod_findhash(NULL, hashtype);

		checkpasswd = strrchr(checkpasswd + 1, '$');
		if (checkpasswd)
			checkpasswd++;
		if (hash && checkpasswd)
		{
			char b64passwd[50] = {0};
			int length = _authz_computepasswd(hash, user,
						realm, passwd, b64passwd, sizeof(b64passwd));

			auth_dbg("auth: check %s %s", b64passwd, checkpasswd);
			if (!strncmp(b64passwd, checkpasswd, length))
				ret = ESUCCESS;
		}
		else
			err("auth: %.3s not supported change password encryption", checkpasswd);
	}
	else if (!string_cmp(passwd, checkpasswd, -1))
	{
		ret = ESUCCESS;
	}
	return ret;
}

#ifdef AUTH_TOKEN
static size_t _mod_auth_generatetoken(void *arg, http_message_t *request, char **token)
{
	const authz_token_config_t *config = (const authz_token_config_t *)arg;
	size_t _noncelen = config->issuer.length + 1 + 24 + 1 + sizeof(time_t);
	size_t tokenlen = _noncelen + (_noncelen + 2) / 3;
	*token = calloc(2, tokenlen + 1);
	char *_nonce = calloc(1, _noncelen + 1);
	int i;
	for (i = 0; i < (24 / sizeof(int)); i++)
	{
		*(int *)(_nonce + i * 4) = random();
	}
	_nonce[24] = '.';
	time_t expire = (config->expire * 60);
	if (expire == 0)
		expire = 60 * 30;
	expire += time(NULL);
	memcpy(&_nonce[25], &expire, sizeof(time_t));
	if (config->issuer.data != NULL)
	{
		_nonce[25 + sizeof(time_t)] = '.';
		memcpy(&_nonce[25 + sizeof(time_t) + 1], config->issuer.data, config->issuer.length);
	}
	tokenlen = base64_urlencoding->encode(_nonce, _noncelen, *token, tokenlen);
	free(_nonce);
	return tokenlen;
}

static int _authn_checktoken(const authz_token_config_t *config, const char *token)
{
	if (config->type  == E_JWT)
		return authn_jwt_checktoken(config, token);

	size_t _noncelen = config->issuer.length + 1 + 24 + 1 + sizeof(time_t);
	char *_nonce = calloc(1, _noncelen + 1);
	size_t tokenlen = _noncelen + (_noncelen + 2) / 3;
	tokenlen = strnlen(token, tokenlen);
	_noncelen = base64_urlencoding->decode(token, tokenlen, _nonce, _noncelen);
	time_t expire;
	memcpy(&expire, &_nonce[25], sizeof(time_t));
	free(_nonce);
	if (expire < time(NULL))
	{
		err("auth: token expired");
		return EREJECT;
	}
	return ESUCCESS;
}

static const char *_authn_gettoken(const _mod_auth_ctx_t *ctx, http_message_t *request, const char **token, size_t *tokenlen)
{
	const _mod_auth_t *mod = ctx->mod;
	const char *authorization = NULL;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authn->type & AUTHN_HEADER_E)
	{
		*tokenlen = httpmessage_REQUEST2(request, str_xtoken, token);
	}
	if (*tokenlen == 0)
		*tokenlen = httpmessage_cookie(request, str_xtoken, token);
	if (*tokenlen > 0)
	{
		authorization = strrchr(*token, '.');
		if (authorization == NULL)
			authorization = *token;
		else
			authorization++;
		return authorization;
	}
	return NULL;
}

static const char *_authn_gettokenuser(const _mod_auth_ctx_t *ctx, http_message_t *request)
{
	const _mod_auth_t *mod = ctx->mod;
	const char *user = NULL;
	size_t length = 0;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authn->type & AUTHN_HEADER_E)
		length = httpmessage_REQUEST2(request, str_xuser, &user);
	if (length == 0)
		length = httpmessage_cookie(request, str_xuser, &user);
	if (length == 0)
		user = str_anonymous;
	return user;
}

static size_t _authn_signtoken(const char *key, size_t keylen,
		const char *data, size_t datalen,
		char *b64signature, size_t b64signaturelen)
{
	size_t length = 0;

	if (hash_macsha256 != NULL && key != NULL)
	{
		void *ctx = hash_macsha256->initkey(key, keylen);
		if (ctx)
		{
			hash_macsha256->update(ctx, data, datalen);
			char signature[HASH_MAX_SIZE];
			size_t signlen = hash_macsha256->finish(ctx, signature);
			if (b64signaturelen < signlen)
			{
				err("auth: signature buffer too small");
				return -1;
			}
			length = base64_urlencoding->encode(signature, signlen, b64signature, b64signaturelen);
			auth_dbg("auth: signature %s", b64signature);
		}
	}
	return length;
}

int authn_checksignature(const char *key, size_t keylen,
		const char *data, size_t datalen,
		const char *sign, size_t signlen)
{
	char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
	size_t len =_authn_signtoken(key, keylen, data, datalen, b64signature, sizeof(b64signature));
	if (len == (size_t)-1)
		return EREJECT;
	string_t signature = {0};
	string_store(&signature, b64signature, len);
	if (string_cmp(&signature, sign, signlen))
		return EREJECT;
	return ESUCCESS;
}

static int authn_checktoken(_mod_auth_ctx_t *ctx, authz_t *authz, const char *token, size_t tokenlen, const char *sign, size_t signlen, const char **user)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;

	const char *key = mod->config->token.secret.data;
	size_t keylen = mod->config->token.secret.length;
	ret = authn_checksignature(key, keylen, token, tokenlen, sign, signlen);
	if (ret == ESUCCESS)
	{
		ret = _authn_checktoken(&mod->config->token, token);
	}
	else
		err("auth: token with bad signature %.*s", (int)signlen, sign);
	if (ret == ESUCCESS)
	{
		/// some authz may join a token to an user
		*user = authz->rules->check(authz->ctx, NULL, NULL, token);
	}
	return ret;
}
#endif

static size_t _authn_getauthorization(const _mod_auth_ctx_t *ctx, http_message_t *request, const char **authorization)
{
	const _mod_auth_t *mod = ctx->mod;
	size_t authorizationlen = 0;
	/**
	 * with standard authentication, the authorization code
	 * is sended info header
	 */
	authorizationlen = httpmessage_REQUEST2(request, str_authorization, authorization);
	if (authorizationlen != 0 && string_cmp(&mod->type, *authorization, -1))
	{
		err("auth: type mismatch %.*s, %.*s", (int)mod->type.length, *authorization, (int)mod->type.length, mod->type.data);
		*authorization = NULL;
		authorizationlen = 0;
	}
	/**
	 * to send the authorization header only once, the "cookie"
	 * option of the server store the authorization inside cookie.
	 * This method allow to use little client which manage only cookie.
	 */
	if (authorizationlen == 0)
	{
		string_t cookie = {0};
		string_t tauthorization = STRING_DCL(str_authorization);
		if (cookie_get2(request, &tauthorization, &cookie) == ESUCCESS)
		{
			authorizationlen = string_length(&cookie);
			*authorization = string_toc(&cookie);
		}
		auth_dbg("auth: cookie get %p", *authorization);
	}
	return authorizationlen;
}

static int _authn_setauthorization_cookie(const _mod_auth_ctx_t *ctx,
			const string_t *authorization,
			const string_t *token, const string_t *sign,
			http_message_t *response)
{
	string_t tsecure = STRING_DCL("; Secure");
	string_t tpoint = STRING_DCL(".");
	string_t tsamesitelax = STRING_DCL("; Samesite=Lax");
	_mod_auth_t *mod = ctx->mod;
	if (!string_empty(token))
	{
		string_t txtoken = STRING_DCL(str_xtoken);
		if (string_empty(sign))
			cookie_set(response, &txtoken, token, &tsecure, &tsamesitelax, NULL);
		else
			cookie_set(response, &txtoken, token, &tpoint, sign, &tsecure, &tsamesitelax, NULL);
	}
	const char *user = NULL;
	size_t userlen = auth_info2(response, str_user, &user);
	string_t tuser = {0};
	string_store(&tuser, user, userlen);
	string_t txuser = STRING_DCL(str_xuser);
	cookie_set(response, &txuser, &tuser, NULL);

	const char *group = NULL;
	size_t grouplen = auth_info2(response, str_group, &group);
	string_t tgroup = {0};
	string_store(&tgroup, group, grouplen);
	if (!string_empty(&tgroup))
	{
		string_t txgroup = STRING_DCL(str_xgroup);
		cookie_set(response, &txgroup, &tgroup, NULL);
	}

	const char *home = auth_info(response, STRING_REF(str_home));
	if (home && home[0] != '\0')
	{
		string_t ttylde = STRING_DCL("~/");
		string_t txhome = STRING_DCL(str_xhome);
		cookie_set(response, &txhome, &ttylde, NULL);
	}
	return ESUCCESS;
}

static int _authn_setauthorization_header(const _mod_auth_ctx_t *ctx,
			const string_t *authorization, const string_t *token, const string_t *sign,
			http_message_t *response)
{
	_mod_auth_t *mod = ctx->mod;

	if (!string_empty(token))
	{
		httpmessage_addheader(response, str_xtoken, string_toc(token), string_length(token));
		if (!string_empty(sign))
		{
			httpmessage_appendheader(response, str_xtoken, STRING_REF("."));
			httpmessage_appendheader(response, str_xtoken, string_toc(sign), string_length(sign));
		}
	}
	const char *user = NULL;
	size_t userlen = auth_info2(response, str_user, &user);
	httpmessage_addheader(response, str_xuser, user, userlen);
	httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xuser));
	const char *group = NULL;
	size_t grouplen = auth_info2(response, str_group, &group);
	if (group && grouplen > 0)
	{
		httpmessage_addheader(response, str_xgroup, group, grouplen);
		httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xgroup));
	}
	const char *home = auth_info(response, STRING_REF(str_home));
	if (home && home[0] != '\0')
	{
		httpmessage_addheader(response, str_xhome, STRING_REF("~/"));
	}
	return ESUCCESS;
}

static const char * _authn_checkauthorization(_mod_auth_ctx_t *ctx, authn_t *authn, authz_t *authz,
		const char *authorization, size_t authorizationlen, http_message_t *request)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	const char *authentication = strchr(authorization, ' ');
	const char *method = NULL;
	size_t methodlen = httpmessage_REQUEST2(request, "method", &method);
	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request, "uri", &uri);

	if (authentication)
	{
		authentication++;
		authorizationlen -= authentication - authorization;
	}
	else
		authentication = authorization;
	/**
	 * The current authentication is made by the client (the browser).
	 * In this case the client compute the autorization for each file to download.
	 * With redirection to the login page, all files should contain the code
	 * to compute the autorizarion. But it is impossible to do it. Then
	 * only the method HEAD is used to login and the client must send
	 * same autorization for all files to download.
	 * WARNING: It is incorrect to use this method for security.
	 * The authorization is always acceptable and it is dangerous.
	 */
	if (!string_empty(&config->redirect))
	{
		method = str_head;
		methodlen = sizeof(str_head) - 1;
	}
	const char *user = authn->rules->check(authn->ctx, authz, method, methodlen, uri, urilen, authentication, authorizationlen);
	return user;
}

static int _authn_check(_mod_auth_ctx_t *ctx, authz_t *authz, http_message_t *request, const char **authorization, const char **user)
{
	_mod_auth_t *mod = ctx->mod;
	int ret = ECONTINUE;
	const char *tuser = NULL;

	/// authn may use setup for initialize some data, and the ctx change with client
	authn_t *authn = mod->authn;
	if (ctx->authn.ctx)
		authn = &ctx->authn;
	if (authn->rules->check)
	{
		size_t authorizationlen = _authn_getauthorization(ctx, request, authorization);
		if (authorizationlen > 0)
			tuser = _authn_checkauthorization( ctx, authn, authz, *authorization, authorizationlen, request);
	}
	else if (authn->rules->checkrequest)
	{
		tuser = authn->rules->checkrequest(authn->ctx, authz, request);
	}
	if (tuser != NULL)
	{
		*user = tuser;
		ret = EREJECT;
	}
	return ret;
}
static int auth_redirect_uri(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;

	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request, "uri", &uri);
	const char *query = NULL;
	size_t querylen = httpmessage_REQUEST2(request, "query", &query);
	if (utils_searchexp(query, "noredirect", NULL) == ESUCCESS)
		return ret;

	httpmessage_addheader(response, str_location, config->redirect.data, config->redirect.length);

	// if redirect_uri is present, the next one must not be added
	char sep = '?';
	if (strchr(config->redirect.data, sep))
		sep = '&';
	if ((config->authn.type & AUTHN_REDIRECT_E) &&
		(utils_searchexp(query, "redirect_uri", NULL) != ESUCCESS))
	{
		http_server_t *server = httpclient_server(httpmessage_client(request));
		httpmessage_appendheader(response, str_location, &sep, 1);
		sep = '&';
		httpmessage_appendheader(response, str_location, STRING_REF("redirect_uri"));
		httpmessage_appendheader(response, str_location, STRING_REF("="));
		/// append redirect_uri if not exist other with it will append later with query part
		const char *scheme = NULL;
		size_t schemelen = httpserver_INFO2(server, "scheme", &scheme);
		httpmessage_appendheader(response, str_location, scheme, schemelen);
		httpmessage_appendheader(response, str_location, STRING_REF("://"));
		const char *host = NULL;
		size_t hostlen = httpserver_INFO2(server, "hostname", &host);
		if (hostlen == 0)
		{
			hostlen = httpmessage_REQUEST2(request, "addr", &host);
		}
		httpmessage_appendheader(response, str_location, host, hostlen);
		const char *port = NULL;
		size_t portlen = httpserver_INFO2(server, "port", &port);
		if (portlen != 0)
		{
			httpmessage_appendheader(response, str_location, STRING_REF(":"));
			httpmessage_appendheader(response, str_location, port, portlen);
		}
		httpmessage_appendheader(response, str_location, uri, urilen);
	}
	if (query && query[0] != '\0')
	{
		httpmessage_appendheader(response, str_location, &sep, 1);
		httpmessage_appendheader(response, str_location, query, querylen);
	}

	ret = ESUCCESS;

	return ret;
}

static int _authn_challenge(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	const char *uri = httpmessage_REQUEST(request, "uri");

	if (mod->authn->ctx)
	{
		ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	}
	else
	{
		err("auth: error during configuration, server locked");
		httpmessage_result(response, RESULT_511);
		ret = ESUCCESS;
	}
	if (ret == ECONTINUE)
	{
		/// In MFA usage, the second step may set a challenge but the
		/// cookie contains information for the first step and we should to keep it
		/// In normal usage the challenge is set before any Cookie creation.
		/// If the token is present and we have a challenge, the cookie is bad.
		/// But it is not dangerous to keep it, because we send a new challenge.
#if 0
		/// ---reset the Cookie to remove it on the client---
		if (mod->authn->type & AUTHN_COOKIE_E)
			cookie_set(response, "X-Auth-Token", "", ";Max-Age=0", NULL);
#endif

		ret = ESUCCESS;
		auth_dbg("auth: challenge failed");
		const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
		if (X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL)
		{
			/// request from XMLHttpRequest was coming from JS script.
			/// The page tried an authentication and want to stay on top.
			httpmessage_result(response, RESULT_403);
		}
		else if (config->redirect.data)
		{
			int protect = 1;
			/**
			 * check the url redirection
			 */
			const char *redirect = strstr(config->redirect.data, "://");
			if (redirect != NULL)
			{
				redirect += 3;
				redirect = strchr(redirect, '/');
			}
			else
				redirect = config->redirect.data;
			if (redirect[0] == '/')
				redirect++;
			protect = utils_searchexp(uri, redirect, NULL);
			if (protect == ESUCCESS)
			{
				/**
				 * the request URI is the URL of the redirection
				 * the authentication has to accept (this module
				 * reject to manage the request and another module
				 * should send response to the request.
				 */
				warn("auth: accept redirection on challenge");
				httpmessage_result(response, RESULT_200);
				ret = EREJECT;
			}
			else
			{
				ret = auth_redirect_uri(ctx, request, response);
				httpmessage_result(response, RESULT_302);
			}
		}
		else
		{
			httpmessage_result(response, RESULT_401);
		}
	}
	return ret;
}

static int _authn_checkuri(const mod_auth_t *config, http_message_t *request, http_message_t *response)
{
	const char *uri = httpmessage_REQUEST(request, "uri");
	int ret = ECONTINUE;
	int protect = 1;

	/// the access to home file needs an authorization
	if (strchr(uri, '~') != NULL)
		return ret;
	/**
	 * check uri
	 */
	protect = utils_searchexp(uri, config->unprotect, NULL);
	if (protect == ESUCCESS)
	{
		auth_dbg("unprotected uri %s", config->unprotect);
		ret = EREJECT;
	}
	protect = utils_searchexp(uri, config->protect, NULL);
	if (protect == ESUCCESS)
	{
		auth_dbg("protected uri %s", config->protect);
		httpmessage_result(response, RESULT_403);
		ret = ESUCCESS;
	}
	protect = utils_searchexp(uri, config->token_ep.data, NULL);
	if (protect == ESUCCESS)
	{
		auth_dbg("protected uri %s", config->token_ep.data);
		httpmessage_result(response, RESULT_403);
		ret = ESUCCESS;
	}
	return ret;
}

static int auth_saveinfo(void *arg, const char *key, size_t keylen, const char *value, size_t valuelen)
{
	int ret = ECONTINUE;
	http_client_t *clt = (http_client_t *)arg;

	httpclient_session(clt, key, keylen, value, valuelen);
	return ret;
}

static int _auth_prepareresponse(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response,
					const char *cauthorization, const char *ctoken)
{
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	string_t authorization = {0};
	string_store(&authorization, cauthorization, -1);
	string_t token = {0};
	string_store(&token, ctoken, -1);
	string_t sign = {0};

	char *ttoken = NULL;
	size_t ttokenlen = -1;
	char *tsign = NULL;
	size_t tsignlen = -1;
#ifdef AUTH_TOKEN
	if (string_empty(&token) && config->authz.type & AUTHZ_TOKEN_E)
	{
		ttokenlen = mod->generatetoken(&mod->config->token, request, &ttoken);
		string_store(&token, ttoken, ttokenlen);

		tsignlen = (int)(HASH_MAX_SIZE * 1.5) + 1;
		tsign = calloc(1, tsignlen);

		const char *key = mod->config->token.secret.data;
		size_t keylen = mod->config->token.secret.length;
		tsignlen = _authn_signtoken(key, keylen, ttoken, ttokenlen, tsign, tsignlen);
		if (tsign == NULL)
			httpclient_session(ctx->clt, STRING_REF(str_token), ttoken, ttokenlen);
		else
			httpclient_session(ctx->clt, STRING_REF(str_token), tsign, tsignlen);
		string_store(&sign, tsign, tsignlen);

		char strexpire[100];
		size_t lenexpire = snprintf(strexpire, 100, "max-age=%lu, must-revalidate", config->token.expire * 60);
		httpmessage_addheader(response, str_cachecontrol, strexpire, lenexpire);
	}
#endif

	if (mod->authn->type & AUTHN_HEADER_E)
	{
		_authn_setauthorization_header(ctx, &authorization, &token, &sign, response);
	}
	else if (mod->authn->type & AUTHN_COOKIE_E)
	{
		_authn_setauthorization_cookie(ctx, &authorization, &token, &sign, response);
	}

	if (mod->authz->type & AUTHZ_CHOWN_E)
	{
		const char *user = auth_info(request, STRING_REF(str_user));
		ouistiti_setprocessowner(user);
	}
	if (ttoken)
		free(ttoken);
	if (tsign)
		free(tsign);
	return ESUCCESS;
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	const _mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *authorization = NULL;
	const char *token = NULL;

	/**
	 * authz may need setup the user setting for each message
	 **/
	authz_t ctx_authz = {0};
	authz_t *authz = mod->authz;
	if(mod->authz->rules->setup)
	{
		ctx_authz.ctx = mod->authz->rules->setup(mod->authz->ctx);
		ctx_authz.rules = mod->authz->rules;
		ctx_authz.type = mod->authz->type;
		authz = &ctx_authz;
	}

	const char *user = NULL;
#ifdef AUTH_TOKEN
	if (mod->authn->type & AUTHN_TOKEN_E || authz->type & AUTHZ_TOKEN_E)
	{
		size_t tokenlen = 0;
		authorization = _authn_gettoken(ctx, request, &token, &tokenlen);
		auth_dbg("auth: gettoken %s", token);
		if (mod->authn->ctx && authorization != NULL && authorization[0] != '\0' &&
					token != NULL)
		{
			size_t authorizationlen = tokenlen - (authorization - token);
			/// the signature is concated to the end of token
			/// only the token part must be checked
			/// remove the signature and the leading dot to the tokenlen
			if (authn_checktoken( ctx, authz, token, tokenlen - authorizationlen - 1, authorization, authorizationlen, &user) == ESUCCESS)
			{
				ret = EREJECT;
			}
			else
				token = NULL;
			auth_dbg("auth: checktoken %d", ret);
		}
		if (ret == EREJECT)
			user = _authn_gettokenuser(ctx, request);
	}
#endif
	if (ret == ECONTINUE)
	{
		/**
		 * The header WWW-Authenticate inside the request
		 * allows to disconnect the user.
		 */
		authorization = httpmessage_REQUEST(request, str_authenticate);
		if (authorization != NULL && authorization[0] != '\0')
		{
			ret = ESUCCESS;
		}
		auth_dbg("auth: authenticate %d", ret);
	}

	if (ret == ECONTINUE)
	{
		ret = _authn_check(ctx, authz, request, &authorization, &user);
		auth_dbg("auth: checkauthorization %d", ret);
	}
	string_t issuer = {0};
	if (ret != EREJECT)
	{
		const char *issuerdata = NULL;
		size_t length = auth_info2(request, str_issuer, &issuerdata);
		string_store(&issuer, issuerdata, length);
		if (!string_contain(&issuer, string_toc(&config->token.issuer), string_length(&config->token.issuer), '+'))
		{
			warn("auth: session's issuer (%s) already set, by-pass the token checking", string_toc(&config->token.issuer));
			auth_info2(request, str_user, &user);
			authorization = issuerdata;
			ret = EREJECT;
		}
	}
	if (ret == EREJECT)
	{
		const char *sessionuser = NULL;
		auth_info2(request, str_user, &sessionuser);
		if (sessionuser && strcmp(user, sessionuser))
		{
			httpmessage_result(response, RESULT_500);
			ret = ESUCCESS;
		}
	}

	if (ret == ECONTINUE)
	{
		/// any authorization doesn't satisfy the authentication
		authorization = NULL;
		ret = _authn_checkuri(config, request, response);
		auth_dbg("auth: checkuri %d", ret);
	}

	if (ret != EREJECT)
	{
		httpclient_dropsession(ctx->clt);
		ret = _authn_challenge(ctx, request, response);
	}
	else if (authorization != NULL)
	{
		if (httpclient_setsession(ctx->clt, authorization, -1) == EREJECT)
		{
			auth_dbg("auth: session already open");
			httpclient_appendsession(ctx->clt, str_issuer, "+", 1);
			httpclient_appendsession(ctx->clt, str_issuer, STRING_INFO(config->token.issuer));
		}
		else
		{
			auth_dbg("auth: set the session");
			authz->rules->setsession(authz->ctx, user, token, auth_saveinfo, ctx->clt);
			httpclient_session(ctx->clt, STRING_REF(str_issuer), STRING_INFO(config->token.issuer));
			if (authz->rules->join)
			{
				authz->rules->join(authz->ctx, user, authorization, mod->config->token.expire);
			}
		}
		char issuerdata[254];
		size_t length = 0;
		if (authz->rules->issuer)
			length = authz->rules->issuer(authz->ctx, user, issuerdata, sizeof(issuerdata));
		if (length > 0)
		{
			httpclient_appendsession(ctx->clt, str_issuer, "+", 1);
			httpclient_appendsession(ctx->clt, str_issuer, issuerdata, length);
		}
		dbg("auth: type %s", (const char *)httpclient_session(ctx->clt, STRING_REF("authtype"), NULL, 0));
		const char *user = auth_info(request, STRING_REF(str_user));
		const char *status = auth_info(request, STRING_REF(str_status));
		if (status && !strcmp(status, str_status_reapproving))
		{
			warn("auth: user \"%s\" accepted from %p to change password", user, ctx->clt);
			httpclient_session(ctx->clt, STRING_REF(str_group), STRING_REF(str_status_reapproving));
			ret = EREJECT;
		}
		else if (status && strcmp(status, str_status_activated) != 0)
		{
			err("auth: user \"%s\" is not yet activated (%s) from %p", user, status, ctx->clt);
			httpclient_dropsession(ctx->clt);
			return _authn_challenge(ctx, request, response);
		}
		else
		{
			warn("auth: user \"%s\" accepted from %p", user, ctx->clt);
			ret = EREJECT;
		}
		_auth_prepareresponse(ctx, request, response, authorization, token);
	}
	else
	{
		warn("auth: accepted without authorization (unprotect files, shortcut,...) from %p", ctx->clt);
	}
	/**
	 * As the setup, the authz may need to cleanup between each message
	 **/
	if (authz->ctx  && authz->rules->cleanup)
	{
		authz->rules->cleanup(authz->ctx);
		authz->ctx = NULL;
	}
	return ret;
}

const module_t mod_auth =
{
	.version = 0x01,
	.name = str_auth,
	.configure = (module_configure_t)&auth_config,
	.create = (module_create_t)&mod_auth_create,
	.destroy = &mod_auth_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_auth")));
#endif
