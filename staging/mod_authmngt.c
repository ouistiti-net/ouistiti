/*****************************************************************************
 * mod_authmngt.c: Authentication management module
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
#include <pwd.h>
#include <time.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"

#include "mod_auth.h"
#include "mod_authmngt.h"

#include "authmngt_sqlite.h"

#define authmngt_dbg(...)

typedef struct _mod_authmngt_s _mod_authmngt_t;

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_authmngt[] = "authmngt";

struct _mod_authmngt_s
{
	mod_authmngt_t *config;
};

typedef struct _mod_authmngt_ctx_s _mod_authmngt_ctx_t;
struct _mod_authmngt_ctx_s
{
	_mod_authmngt_t *mod;
	http_client_t *clt;
	void *ctx;
	const char *error;
	int list;
	unsigned int isroot:1;
	unsigned int isuser:1;
};

static void *mod_authmngt_getctx(void *arg, http_client_t *ctl, struct sockaddr *UNUSED(addr), int UNUSED(addrsize));
static void mod_authmngt_freectx(void *arg);

static const char str_mngtpath[] = "^/auth/mngt*";

static const char error_usernotfound[] = "user not found";
static const char error_userexists[] = "user existing";
static const char error_accessdenied[] = "access denied";
static const char error_badvalue[] = "bad value";

#ifdef FILE_CONFIG
#ifdef AUTHZ_SQLITE
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

static void *authmngt_sqlite_config(const config_setting_t *configauth)
{
	authz_sqlite_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "dbname", (const char **)&path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->dbname = path;
	}
	const char *algo = NULL;
	if (config_setting_lookup_string(configauth, "algorithm", &algo) == CONFIG_TRUE)
		authz_config->hash = _mod_findhash(algo, -1);
	return authz_config;
}
#endif

struct _authmngt_s
{
	void *(*config)(const config_setting_t *);
	authmngt_rules_t *rules;
	const char *name;
};

static const struct _authmngt_s *authmngt_list[] =
{
#ifdef AUTHZ_SQLITE
	&(struct _authmngt_s){
		.config = &authmngt_sqlite_config,
		.rules = &authmngt_sqlite_rules,
		.name = "sqlite",
	},
#endif
};

static int authmngt_setrules(const config_setting_t *configauth, mod_authmngt_t *mngtconfig)
{
	for (int i = 0; i < (sizeof(authmngt_list) / sizeof(*authmngt_list)) && authmngt_list[i]; i++)
	{
		mngtconfig->mngt.config = authmngt_list[i]->config(configauth);
		if (mngtconfig->mngt.config != NULL)
		{
			authmngt_dbg("authmngt: manager %s", authmngt_list[i]->name);
			mngtconfig->mngt.rules = authmngt_list[i]->rules;
			break;
		}
	}
	if (mngtconfig->mngt.rules == NULL)
		return EREJECT;
	return ESUCCESS;
}

static int mod_authmngt_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int conf_ret = ESUCCESS;
	mod_authmngt_t *mngtconfig = NULL;
	static mod_authmngt_issuer_t *issuers = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *config = config_setting_get_member(iterator, "auth");
#else
	const config_setting_t *config = config_setting_lookup(iterator, "auth");
#endif
	if (index == 0)
		issuers = NULL;
	if (config && config_setting_is_list(config))
	{
			if (index >= config_setting_length(config))
				return EREJECT;
			config = config_setting_get_elem(config, index);
			conf_ret = ECONTINUE;
	}
	if (config)
	{
		const char *issuername = NULL;
		if (config_setting_lookup_string(config, "issuer", &issuername) == CONFIG_TRUE)
		{
			mod_authmngt_issuer_t *issuer = calloc(1, sizeof(*issuer));
			string_store(&issuer->name, issuername, -1);
			issuer->next = issuers;
			issuers = issuer;
		}

		const char *mode = NULL;
		int ret = config_setting_lookup_string(config, "options", &mode);
		if ((ret == CONFIG_TRUE) &&
			(utils_searchexp("management", mode, NULL) == ESUCCESS))
		{
			mngtconfig = calloc(1, sizeof(*mngtconfig));
			mngtconfig->issuers = issuers;
			if (authmngt_setrules(config, mngtconfig) != ESUCCESS)
			{
				free(mngtconfig);
				mngtconfig = NULL;
			}
		}
	}
	if ((mngtconfig == NULL) && (conf_ret == ESUCCESS)) //the config is an object
		conf_ret = EREJECT;
	*modconfig = (void *)mngtconfig;
	return conf_ret;
}
#else
static const mod_authmngt_t g_authmngt_config =
{
	.mngt = &(authmngt_t){
		.config = &(authz_sqlite_config_t){
			.dbname = "/etc/ouistiti/auth.db",
		},
		.rules = &authmngt_sqlite_rules,
		.name = "sqlite",
	},
};

static void *mod_authmngt_config(void *iterator, server_t *server)
{
	return (void *)&g_authmngt_config;
}
#endif

static void *mod_authmngt_create(http_server_t *server, mod_authmngt_t *config)
{
	_mod_authmngt_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	httpserver_addmethod(server, METHOD(str_post), MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmethod(server, METHOD(str_put), MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmethod(server, METHOD(str_delete), MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmod(server, mod_authmngt_getctx, mod_authmngt_freectx, mod, "authmngt");

	return mod;
}

static void *mod_authmngt_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;
	_mod_authmngt_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	ctx->clt = clt;
	httpclient_addconnector(clt, _authmngt_connector, ctx, CONNECTOR_DOCUMENT, "authmngt");

	return ctx;
}

static void mod_authmngt_freectx(void *arg)
{
	_mod_authmngt_ctx_t *ctx = (_mod_authmngt_ctx_t *)arg;
	_mod_authmngt_t *mod = ctx->mod;

	if (ctx->ctx  && mod->config->mngt.rules->destroy)
	{
		mod->config->mngt.rules->destroy(ctx->ctx);
	}
	free(ctx);
}

static void mod_authmngt_destroy(void *arg)
{
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;
#ifdef FILE_CONFIG
	mod_authmngt_issuer_t *next;
	for (mod_authmngt_issuer_t *issuer = mod->config->issuers; issuer != NULL; issuer = next)
	{
		next = issuer->next;
		free(issuer);
	}
	free(mod->config);
#endif
	free(mod);
}

static int authmngt_jsonifyuser(_mod_authmngt_ctx_t *ctx, http_message_t *response, const authsession_t *info)
{
	if (info->user[0] == '\0')
		return EREJECT;

	httpmessage_appendcontent(response, STRING_REF("{"));
	httpmessage_appendcontent(response, STRING_REF("\"user\":\""));
	httpmessage_appendcontent(response, info->user, -1);
	httpmessage_appendcontent(response, STRING_REF("\""));
	if (info->group[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF(",\"group\":\""));
		httpmessage_appendcontent(response, info->group, -1);
		httpmessage_appendcontent(response, STRING_REF("\""));
	}
	if (info->status[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF(",\"status\":\""));
		httpmessage_appendcontent(response, info->status, -1);
		httpmessage_appendcontent(response, STRING_REF("\""));
	}
	if (info->home[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF(",\"home\":\""));
		httpmessage_appendcontent(response, info->home, -1);
		httpmessage_appendcontent(response, STRING_REF("\""));
	}
	if (info->token[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF(",\"token\":\""));
		httpmessage_appendcontent(response, info->token, -1);
		httpmessage_appendcontent(response, STRING_REF("\""));
	}
	if (info->passwd[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF(",\"passwdchanged\":true"));
	}
	_mod_authmngt_t *mod = ctx->mod;
	char issuers[254] = {0};
	size_t length = mod->config->mngt.rules->issuer(ctx->ctx, info->user, issuers, sizeof(issuers));
	if (length > 0)
	{
		httpmessage_appendcontent(response, STRING_REF(",\"issuers\":{"));
		const char *issuer = issuers;
		const char *end = strchr(issuer, '+');
		for (; end != NULL; end = strchr(end + 1, '+'))
		{
			httpmessage_appendcontent(response, STRING_REF("\""));
			httpmessage_appendcontent(response, issuer, end - issuer);
			httpmessage_appendcontent(response, STRING_REF("\":false,"));
			length -= end - issuer + 1;
			issuer = end + 1;
		}
		httpmessage_appendcontent(response, STRING_REF("\""));
		httpmessage_appendcontent(response, issuer, length);
		httpmessage_appendcontent(response, STRING_REF("\":false"));
		httpmessage_appendcontent(response, STRING_REF("}"));
	}
	httpmessage_appendcontent(response, STRING_REF("}"));
	return ESUCCESS;
}

static int authmngt_stringifyuser(_mod_authmngt_ctx_t *UNUSED(ctx), http_message_t *response, const authsession_t *info)
{
	if (info->user[0] == '\0')
		return EREJECT;

	httpmessage_appendcontent(response, STRING_REF(str_user));
	httpmessage_appendcontent(response, STRING_REF("="));
	httpmessage_appendcontent(response, info->user, -1);
	if (info->group[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF("&"));
		httpmessage_appendcontent(response, STRING_REF(str_group));
		httpmessage_appendcontent(response, STRING_REF("="));
		httpmessage_appendcontent(response, info->group, -1);
	}
	if (info->status[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF("&"));
		httpmessage_appendcontent(response, STRING_REF(str_status));
		httpmessage_appendcontent(response, STRING_REF("="));
		httpmessage_appendcontent(response, info->status, -1);
	}
	if (info->home[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF("&"));
		httpmessage_appendcontent(response, STRING_REF(str_home));
		httpmessage_appendcontent(response, STRING_REF("="));
		httpmessage_appendcontent(response, info->home, -1);
	}
	if (info->token[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF("&"));
		httpmessage_appendcontent(response, STRING_REF(str_token));
		httpmessage_appendcontent(response, STRING_REF("="));
		httpmessage_appendcontent(response, info->token, -1);
	}
	if (info->passwd[0] != '\0')
	{
		httpmessage_appendcontent(response, STRING_REF("&"));
		httpmessage_appendcontent(response, STRING_REF("passwdchanged=true"));
	}
	return 0;
}

static int _authmngt_checkrights(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request)
{
	const char *auth = auth_info(request, STRING_REF(str_user));
	if (auth && user)
		ctx->isuser = !strcmp(auth, user);
	const char *group = auth_info(request, STRING_REF(str_group));
	if (group && !strcmp(group, "root"))
	{
		ctx->isroot = 1;
		ctx->isuser = 1;
	}
	return ctx->isuser;
}

static int _authmngt_parsegroup(http_message_t *request, authsession_t *session)
{
	int ret = EREJECT;
	const char *group = NULL;
	size_t length = httpmessage_parameter(request, str_group, &group);
	if (length > 0)
	{
		strncpy(session->group, group, length);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authmngt_parsehome(http_message_t *request, authsession_t *session)
{
	int ret = EREJECT;
	const char *home = NULL;
	size_t length = httpmessage_parameter(request, str_home, &home);
	if (length > 0)
	{
		strncpy(session->home, home, length);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authmngt_parsepasswd(http_message_t *request, authsession_t *session)
{
	int ret = EREJECT;
	const char *passwd = NULL;
	size_t length = httpmessage_parameter(request, "passwd", &passwd);
	if (length > 0)
	{
		char *decode = utils_urldecode(passwd, length);
		if (decode != NULL)
		{
			strncpy(session->passwd, decode, TOKEN_MAX);
			free(decode);
		}
		else
			strncpy(session->passwd, passwd, TOKEN_MAX);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authmngt_parsestatus(http_message_t *request, authsession_t *session)
{
	int ret = EREJECT;
	const char *status = NULL;
	size_t length = httpmessage_parameter(request, str_status, &status);
	if (length > 0)
	{
		strncpy(session->status, status, length);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authmngt_parseissuer(http_message_t *request, string_t *issuer)
{
	int ret = EREJECT;
	const char *data = NULL;
	size_t length = httpmessage_parameter(request, str_issuer, &data);
	if (length > 0)
	{
		char *decode = utils_urldecode(data, length);
		if (decode != NULL)
		{
			string_cpy(issuer, decode, -1);
			free(decode);
		}
		else
			string_cpy(issuer, data, length);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authmngt_parsesession(_mod_authmngt_ctx_t *ctx, const char *user,
	http_message_t *request, authsession_t *session, string_t *issuer)
{
	int isuser = 0;

	if (user == NULL)
	{
		httpmessage_parameter(request, str_user, &user);
	}
	else
	{
		const char *tmpuser = NULL;
		size_t length = httpmessage_parameter(request, str_user, &tmpuser);
		if (length > 0)
			isuser = !strncmp(user, tmpuser, length);
	}
	if (user != NULL)
	{
		char *decode = utils_urldecode(user, -1);
		if (decode != NULL)
		{
			strncpy(session->user, decode, USER_MAX);
			free(decode);
		}
		else
			strncpy(session->user, user, USER_MAX);
	}
	else
		return EREJECT;

	if (ctx->isroot)
		_authmngt_parsegroup(request, session);

	if (ctx->isroot)
		_authmngt_parsehome(request, session);

	if (ctx->isroot)
		_authmngt_parsestatus(request, session);

	if (isuser || ctx->isroot)
		_authmngt_parsepasswd(request, session);

	if (isuser || ctx->isroot)
		_authmngt_parseissuer(request, issuer);

	return ESUCCESS;
}

static int _authmngt_listresponse(_mod_authmngt_ctx_t *ctx, http_message_t *response)
{
	_mod_authmngt_t *mod = ctx->mod;
	int ret = EREJECT;
	authsession_t info = {0};
	if (ctx->ctx && mod->config->mngt.rules->getuser != NULL)
		ret = mod->config->mngt.rules->getuser(ctx->ctx, ctx->list + 1, &info);
	if (ret == ESUCCESS)
	{
		if (ctx->list > 0)
			httpmessage_appendcontent(response, ",", -1);
		ret = authmngt_jsonifyuser(ctx, response, &info);
	}
	if (ret == EREJECT)
	{
		httpmessage_appendcontent(response, "]", -1);
		ctx->list = -1;
	}
	else
	{
		ctx->list++;
	}
	return ECONTINUE;
}

static int _authmngt_userresponse(_mod_authmngt_ctx_t *ctx, authsession_t *info, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const char *http_accept = httpmessage_REQUEST(request, "Accept");

	if (http_accept && strstr(http_accept, "text/json") != NULL)
	{
		httpmessage_addcontent(response, "text/json", "", -1);
		ret = authmngt_jsonifyuser(ctx, response, info);
	}
	else
	{
		httpmessage_addcontent(response, "application/x-www-form-urlencoded", "", -1);
		ret = authmngt_stringifyuser(ctx, response, info);
	}
	return ret;
}

static int _authmngt_errorresponse(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request, http_message_t *response)
{
	const char *http_accept = httpmessage_REQUEST(request, "Accept");
	httpmessage_result(response, RESULT_500);
	if (strstr(http_accept, "text/json") != NULL)
	{
		httpmessage_addcontent(response, "text/json", "{\"method\":\"", -1);
		httpmessage_appendcontent(response, httpmessage_REQUEST(request, "method"), -1);
		httpmessage_appendcontent(response, "\",\"user\":\"", -1);
		httpmessage_appendcontent(response, user, -1);
		httpmessage_appendcontent(response, "\",\"error\":\"", -1);
		httpmessage_appendcontent(response, ctx->error, -1);
		httpmessage_appendcontent(response, "\"}", -1);
	}

	return ESUCCESS;
}

static int _authmngt_getconnector(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request, http_message_t *response)
{
	_mod_authmngt_t *mod = ctx->mod;
	int ret = EREJECT;

	if (user != NULL)
	{
		authsession_t info = {0};
		if (ctx->ctx && mod->config->mngt.rules->setsession != NULL)
			ret = mod->config->mngt.rules->setsession(ctx->ctx, user, &info);
		if (ret == ESUCCESS)
			ret = _authmngt_userresponse(ctx, &info, request, response);
		else
			ctx->error = error_usernotfound;
	}
	else if (ctx->list == 0)
	{
		httpmessage_addcontent(response, "text/json", NULL, -1);
		httpmessage_appendcontent(response, "[", -1);
		ret = _authmngt_listresponse(ctx, response);
	}
	else if (ctx->list > 0)
	{
		httpmessage_addcontent(response, NULL, "", -1);
		ret = _authmngt_listresponse(ctx, response);
	}
	else
	{
		httpmessage_result(response, RESULT_403);
		ret = ESUCCESS;
	}

	return ret;
}

static int _authmngt_deleteconnector(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request, http_message_t *response)
{
	_mod_authmngt_t *mod = ctx->mod;
	int ret = EREJECT;
	if (!_authmngt_checkrights(ctx, user, request))
	{
		ctx->error = error_accessdenied;
	}
	else if (user != NULL && ctx->ctx && mod->config->mngt.rules->removeuser != NULL)
	{
		authsession_t info = {0};
		strncpy(info.user, user, USER_MAX);
		ret = mod->config->mngt.rules->removeuser(ctx->ctx, &info);
		if (ret == EREJECT)
			ctx->error = error_usernotfound;
	}
	else
	{
		ctx->error = error_badvalue;
	}
	return ret;
}

static int _authmngt_putconnector(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request, http_message_t *response)
{
	_mod_authmngt_t *mod = ctx->mod;
	int ret = EREJECT;

	_authmngt_checkrights(ctx, user, request);
	ctx->isuser = 1;

	authsession_t info = {0};
	const char data[254];
	string_t issuer = {0};
	string_store(&issuer, STRING_REF(data));
	ret = _authmngt_parsesession(ctx, user, request, &info, &issuer);
	if (ret == ESUCCESS && mod->config->mngt.rules->adduser != NULL)
	{
		ret = mod->config->mngt.rules->adduser(ctx->ctx, &info);
		if (ret == ESUCCESS && mod->config->mngt.rules->setsession != NULL)
			ret = mod->config->mngt.rules->setsession(ctx->ctx, info.user, &info);
		else
			ctx->error = error_userexists;
		if (ret == ESUCCESS && mod->config->mngt.rules->setissuer != NULL)
		{
			ret = mod->config->mngt.rules->setissuer(ctx->ctx, info.user, string_toc(&issuer), string_length(&issuer));
		}
		else
			ctx->error = error_badvalue;
		if (ret == ESUCCESS)
			ret = _authmngt_userresponse(ctx, &info, request, response);
		if (ret == ESUCCESS)
			httpmessage_result(response, 201);
	}
	else
		ctx->error = error_accessdenied;
	return ret;
}

static int _authmngt_postconnector(_mod_authmngt_ctx_t *ctx, const char *user, http_message_t *request, http_message_t *response)
{
	_mod_authmngt_t *mod = ctx->mod;
	int ret = EREJECT;
	if (!_authmngt_checkrights(ctx, user, request))
	{
		ctx->error = error_accessdenied;
		return ret;
	}

	authsession_t info = {0};
	const char data[254];
	string_t issuer = {0};
	string_store(&issuer, STRING_REF(data));
	ret = _authmngt_parsesession(ctx, user, request, &info, &issuer);

	if (ret == ESUCCESS && ctx->isroot && mod->config->mngt.rules->changeinfo != NULL)
	{
		authmngt_dbg("authmngt: userinfo\n\tuser: %s\n\tstatus: %s\n\tgroup: %s", info.user, info.status, info.group);
		ret = mod->config->mngt.rules->changeinfo(ctx->ctx, &info);
	}
	if (ret == ESUCCESS && ctx->isuser && info.passwd[0] != '\0' && mod->config->mngt.rules->changepasswd != NULL)
	{
		int checkreapproving = 1;
		if (info.status[0] != '\0')
			checkreapproving = 0;
		ret = mod->config->mngt.rules->changepasswd(ctx->ctx, &info);
		if (checkreapproving && !strcmp(info.status, str_status_reapproving) && mod->config->mngt.rules->changeinfo != NULL)
		{
			strncpy(info.status, str_status_activated, FIELD_MAX);
			ret = mod->config->mngt.rules->changeinfo(ctx->ctx, &info);
		}
	}
	if (ret == ESUCCESS && ctx->isroot && !string_empty(&issuer) && mod->config->mngt.rules->setissuer != NULL)
	{
		ret = mod->config->mngt.rules->setissuer(ctx->ctx, user,string_toc(&issuer), string_length(&issuer));
	}
	if (ret == EREJECT)
		ctx->error = error_badvalue;
	return ret;
}

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_authmngt_ctx_t *ctx = (_mod_authmngt_ctx_t *)arg;
	_mod_authmngt_t *mod = ctx->mod;
	const char *uri = httpmessage_REQUEST(request, "uri");
	const char *user = NULL;

	authmngt_dbg("authmngt: search %s", str_mngtpath);
	if (utils_searchexp(uri, str_mngtpath, &user))
		return EREJECT;

	if (ctx->ctx == NULL)
	{
		ctx->ctx = mod->config->mngt.rules->create(ctx->clt, mod->config->mngt.config);
		if (ctx->ctx == NULL)
		{
			httpmessage_result(response, RESULT_500);
			return ESUCCESS;
		}
	}

	const char *method = httpmessage_REQUEST(request, "method");

	while (user && user[0] == '/') user++;
	authmngt_dbg("authmngt: access to %s %s", uri, user);
	if (!strcmp(method, str_get))
	{
		ret = _authmngt_getconnector(ctx, user, request, response);
	}
	else if (!strcmp(method, str_delete))
	{
		ret = _authmngt_deleteconnector(ctx, user, request, response);
	}
	else if (!strcmp(method, str_put))
	{
		ret = _authmngt_putconnector(ctx, user, request, response);
	}
	else if (!strcmp(method, str_post))
	{
		authsession_t info = {0};
		ret = _authmngt_postconnector(ctx, user, request, response);
		if (ret == ESUCCESS && user != NULL && mod->config->mngt.rules->setsession != NULL)
			ret = mod->config->mngt.rules->setsession(ctx->ctx, user, &info);
		else
			ret = EREJECT;
		if (ret == ESUCCESS)
			ret = _authmngt_userresponse(ctx, &info, request, response);
		else
			ctx->error = error_usernotfound;
	}
	if (ret == EREJECT)
	{
		ret = _authmngt_errorresponse(ctx, user, request, response);
	}

	return ret;
}

const module_t mod_authmngt =
{
	.version = 0x01,
	.name = str_authmngt,
	.configure = (module_configure_t)&mod_authmngt_config,
	.create = (module_create_t)&mod_authmngt_create,
	.destroy = &mod_authmngt_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_authmngt")));
#endif
