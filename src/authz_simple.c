/*****************************************************************************
 * authz_simple.c: Check Authentication in configuration file
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
#include <pwd.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_simple.h"

#define auth_dbg(...)

typedef struct authz_simple_config_s authz_simple_config_t;
struct authz_simple_config_s
{
	string_t user;
	string_t passwd;
	string_t group;
	string_t home;
};

typedef authz_simple_config_t authz_simple_t;

#ifdef FILE_CONFIG
void *authz_simple_config(const config_setting_t *configauth)
{
	authz_simple_config_t *authz_config = NULL;

	const char *user = NULL;
	config_setting_lookup_string(configauth, str_user, &user);
	if (user == NULL || user[0] == '0')
		return NULL;

	authz_config = calloc(1, sizeof(*authz_config));
	string_store(&authz_config->user, user, -1);

	const char *passwd = NULL;
	config_setting_lookup_string(configauth, "passwd", &passwd);
	if (passwd != NULL && passwd[0] != '0')
		string_store(&authz_config->passwd, passwd, -1);

	const char *group = NULL;
	config_setting_lookup_string(configauth, str_group, &group);
	if (group != NULL && group[0] != '0')
		string_store(&authz_config->group, group, -1);

	const char *home = NULL;
	config_setting_lookup_string(configauth, str_home, &home);
	if (home != NULL && home[0] != '0')
		string_store(&authz_config->home, home, -1);

	return authz_config;
}
#endif

static void *authz_simple_create(http_server_t *UNUSED(server), void *config)
{
	return config;
}

static int authz_simple_passwd(void *arg,const  char *user, const char **passwd)
{
	const authz_simple_t *ctx = (const authz_simple_t *)arg;
	if (!string_cmp(&ctx->user, user, -1))
	{
		*passwd = ctx->passwd.data;
		return ctx->passwd.length;
	}
	return 0;
}

static const char *authz_simple_check(void *arg, const char *user, const char *passwd, const char *token)
{
	const authz_simple_t *ctx = (const authz_simple_t *)arg;

	if (user != NULL && passwd != NULL &&
		!string_cmp(&ctx->user, user, -1) && !string_empty(&ctx->passwd) &&
		(authz_checkpasswd(passwd, &ctx->user, NULL,  &ctx->passwd) == ESUCCESS))
	{
			return user;
	}
	return NULL;
}

static int authz_simple_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_simple_t *config = (const authz_simple_t *)arg;

	cb(cbarg, STRING_REF(str_user), STRING_INFO(config->user));
	if (!string_empty(&config->group))
		cb(cbarg, STRING_REF(str_group), STRING_INFO(config->group));
	if (!string_empty(&config->home))
		cb(cbarg, STRING_REF(str_home), STRING_INFO(config->home));
	cb(cbarg, STRING_REF(str_status), STRING_REF(str_status_activated));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));
	return ESUCCESS;
}

authz_rules_t authz_simple_rules =
{
	.create = &authz_simple_create,
	.check = &authz_simple_check,
	.passwd = &authz_simple_passwd,
	.setsession = &authz_simple_setsession,
	.destroy = NULL,
};
