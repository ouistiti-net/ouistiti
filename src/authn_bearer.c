/*****************************************************************************
 * authn_bearer.c: Basic Authentication mode
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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authn_bearer.h"

#define auth_dbg(...)

typedef struct authn_bearer_s authn_bearer_t;
struct authn_bearer_s
{
	const authn_t *authn;
	http_client_t *clt;
};

#ifdef FILE_CONFIG
void *authn_bearer_config(const config_setting_t *configauth)
{
	return (void *)1;
}
#endif

static void *authn_bearer_create(const authn_t *authn, void *arg)
{
	authn_bearer_t *mod = calloc(1, sizeof(*mod));
	mod->authn = authn;
	return mod;
}

static int authn_bearer_challenge(void *arg, http_message_t *UNUSED(request), http_message_t *response)
{
	int ret = ECONTINUE;
	const authn_bearer_t *mod = (authn_bearer_t *)arg;
	const mod_auth_t *config = mod->authn->config;

	httpmessage_addheader(response, str_authenticate, STRING_REF("Bearer realm=\""));
	httpmessage_appendheader(response, str_authenticate, config->realm.data, config->realm.length);
	httpmessage_appendheader(response, str_authenticate, STRING_REF("\""));
	return ret;
}

static const char *authn_bearer_check(void *arg, authz_t *authz, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *string, size_t stringlen)
{
	const authn_bearer_t *mod = (authn_bearer_t *)arg;
	(void) method;
	(void) uri;

	if (!strncmp(string, "Bearer ", 7))
		string += 7;
	const char *user = NULL;
	const char *data = string;
	const char *sign = strrchr(string, '.');
	if (sign != NULL)
	{
		size_t signlen = stringlen;
		size_t datalen = sign - data;
		sign++;
		signlen -= sign - string;
		const char *key = mod->authn->config->token.secret.data;
		size_t keylen = mod->authn->config->token.secret.length;
		if (authn_checksignature(key, keylen, data, datalen, sign, signlen) == ESUCCESS)
		{
			user = authz->rules->check(authz->ctx, NULL, NULL, string);
		}
		else
			err("auth: bearer token with bad signature");
	}
	else
		err("auth: bearer unsigned token");
	return user;
}

static void authn_bearer_destroy(void *arg)
{
	authn_bearer_t *mod = (authn_bearer_t *)arg;
	free(mod);
}

authn_rules_t authn_bearer_rules =
{
	.create = &authn_bearer_create,
	.challenge = &authn_bearer_challenge,
	.check = &authn_bearer_check,
	.destroy = &authn_bearer_destroy,
};
