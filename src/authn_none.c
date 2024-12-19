/*****************************************************************************
 * authn_none.c: None Authentication mode
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
 * this module doesn't authenticate the user.
 * It changes the owner of the client process only.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authn_none.h"

#define auth_dbg(...)

typedef struct authn_none_config_s authn_none_config_t;
struct authn_none_config_s
{
	string_t user;
};

typedef struct authn_none_s authn_none_t;
struct authn_none_s
{
	authn_none_config_t *config;
	const authn_t *authn;
	char *challenge;
};

#ifdef FILE_CONFIG
void *authn_none_config(const config_setting_t *configauth)
{
	authn_none_config_t *authn_config = NULL;
	const char *user = NULL;

	authn_config = calloc(1, sizeof(*authn_config));
	config_setting_lookup_string(configauth, str_user, &user);
	if (user != NULL)
	{
		string_store(&authn_config->user, user, -1);
	}
	else
		warn("config: authn_none needs to set the user");
	return authn_config;
}
#endif

static void *authn_none_create(const authn_t *authn, void *arg)
{
	authn_none_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_none_config_t *)arg;
	mod->authn = authn;

	return mod;
}

static int authn_none_challenge(void *UNUSED(arg), http_message_t *UNUSED(request), http_message_t *UNUSED(response))
{
	return EREJECT;
}

static const char *authn_none_check(void *arg, authz_t *UNUSED(authz), const char *UNUSED(method), size_t UNUSED(methodlen), const char *UNUSED(uri), size_t UNUSED(urilen), const char *UNUSED(string), size_t UNUSED(stringlen))
{
	const authn_none_t *mod = (const authn_none_t *)arg;
	const authn_none_config_t *config = mod->config;

	return config->user.data;
}

static void authn_none_destroy(void *arg)
{
	authn_none_t *mod = (authn_none_t *)arg;
	free(mod->config);
	free(mod);
}

authn_rules_t authn_none_rules =
{
	.create = &authn_none_create,
	.challenge = &authn_none_challenge,
	.check = &authn_none_check,
	.destroy = &authn_none_destroy,
};
