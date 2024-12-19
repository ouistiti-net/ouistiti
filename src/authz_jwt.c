/*****************************************************************************
 * authz_jwt.c: Check Authentication on passwd file
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
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

//#include <mbedtls/md.h>
#include <jansson.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_jwt.h"

#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_jwt_s authz_jwt_t;
struct authz_jwt_s
{
	authz_token_config_t *config;
	const char *token;
};

#ifdef FILE_CONFIG
void *authz_jwt_config(const config_setting_t *configauth)
{
	authz_token_config_t *authz_config = calloc(1, sizeof(*authz_config));
	const char *issuer = NULL;

	int ret = config_setting_lookup_string(configauth, str_issuer, &issuer);
	if (ret == CONFIG_TRUE)
	{
		string_store(&authz_config->issuer, issuer, -1);
	}
	return authz_config;
}
#endif

size_t authz_jwt_generatetoken(void *arg, http_message_t *request, char **token)
{
	const authz_token_config_t *config = (const authz_token_config_t *)arg;
#ifdef JWT_FORMATHEADER
	json_t *jheader = json_object();
	json_object_set(jheader, "alg", json_string("HS256"));
	json_object_set(jheader, "typ", json_string("JWT"));
	char *theader = json_dumps(jheader, 0);
	size_t theaderlen = strlen(theader);
	json_decref(jheader);
#else
	char theader[] = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
	size_t theaderlen = sizeof(theader) - 1;
#endif

	json_t *jtoken = json_object();
	const char *user = auth_info(request, STRING_REF(str_user));
	if (user)
	{
		json_t *juser = json_string(user);
		json_object_set(jtoken, str_user, juser);
	}
	const char *home = auth_info(request, STRING_REF(str_home));
	if (home)
	{
		json_t *jhome = json_string(home);
		json_object_set(jtoken, str_home, jhome);
	}
	const char *status = auth_info(request, STRING_REF(str_status));
	if (status)
	{
		json_t *jstatus = json_string(status);
		json_object_set(jtoken, str_status, jstatus);
	}
	const char *group = auth_info(request, STRING_REF(str_group));
	if (group)
	{
		json_t *jroles = json_string(group);
		json_object_set(jtoken, "roles", jroles);
	}
#ifndef DEBUG
	time_t now = time(NULL);
#else
	time_t now = 0;
#endif
	json_t *jexpire = NULL;
	if (config->expire > 0)
	{
		jexpire = json_integer((config->expire * 60) + now);
	}
	else
		jexpire = json_integer((30 * 60) + now);
	json_object_set(jtoken, "exp", jexpire);
	const char *issuer = auth_info(request, STRING_REF(str_issuer));
	if (issuer)
		json_object_set(jtoken, "iss", json_string(issuer));
#ifdef AUTH_OPENID
	json_object_set(jtoken, "sub", juser);
	json_object_set(jtoken, "preferred_username", juser);
	json_object_set(jtoken, "aud", json_string(str_servername));
	json_object_set(jtoken, "iat", json_integer(now));
#endif
	size_t ttokenlen = json_dumpb(jtoken, NULL, 0, 0);
	if (ttokenlen == 0)
		return 0;
	char *ttoken = malloc(ttokenlen);
	json_dumpb(jtoken, ttoken, ttokenlen, 0);
	auth_dbg("jwt: encode %.*s", ttokenlen, ttoken);
	json_decref(jtoken);

	size_t ret = 0;
	size_t length = (theaderlen + 1 + ttokenlen + 1) * 3 / 2;

	*token = calloc(2, length + 1);
	char *offset = *token;
	length *= 2;
	ret = base64_urlencoding->encode(theader, theaderlen, offset, length);
	offset += ret;
	length -= ret;
#ifdef JWT_FORMATHEADER
	free(theader);
#endif

	*offset = '.';
	offset++;
	ret++;
	length--;

	ret += base64_urlencoding->encode(ttoken, ttokenlen, offset, length);
	free(ttoken);
	warn("auth: jwttoken %s", *token);
	/**
	 * the signature is added inside mod_auth
	 */
	return ret;
}

static json_t *jwt_decode_json(const char *id_token, int header)
{
	if (id_token == NULL)
		return NULL;
	const char *b64header = id_token;
	int length = 0;
	json_error_t error;
	char data[1024] = {0};
	json_t *jpayload = NULL;

	const char *b64payload = strchr(b64header, '.');
	long b64payloadlength = 0;
	const char *b64signature = strrchr(b64header, '.');
	if (b64payload == NULL)
		return NULL;

	b64payload++;
	b64payloadlength = b64signature - b64payload;

	if (header)
	{
#ifdef AUTHZ_JWT_CHECKHEADER
		long b64headerlength = 0;
		b64headerlength = b64payload - b64header;
		length = base64_urlencoding->decode(b64header, b64headerlength, data, 1024);
		dbg("id_token header %s", data);
		jpayload = json_loadb(data, length, 0, &error);
		if (jpayload == NULL)
		{
			err("jwt: token error %s", error.text);
		}
#endif
	}
	else
	{
		length = base64_urlencoding->decode(b64payload, b64payloadlength, data, 1024);
		auth_dbg("jwt: decode %s", data);
		jpayload = json_loadb(data, length, 0, &error);
		if (jpayload == NULL)
			err("jwt: decode error %s", error.text);
	}
	return jpayload;
}

static int _jwt_checkexpiration(const json_t *jinfo)
{
	const json_t *jexpire = json_object_get(jinfo, "exp");
	if (jexpire && json_is_integer(jexpire))
	{
		time_t expire = json_integer_value(jexpire);
#ifndef DEBUG
		time_t now = time(NULL);
#else
		time_t now = 1800; // 30 * 60 (set by default
#endif
		if (expire < now)
		{
			err("auth: jwt expired");
			return EREJECT;
		}
	}
	else
	{
		warn("auth: jwt doesn't contain exp");
		return EREJECT;
	}
	return ESUCCESS;
}

static const char *_jwt_get(const json_t *jinfo, const char *key)
{
	const char *value = NULL;
	const json_t *jvalue = json_object_get(jinfo, key);
	if (jvalue && json_is_string(jvalue))
		value = json_string_value(jvalue);
	return value;
}

static const char *_jwt_getuser(const json_t *jinfo)
{
	const char *user = NULL;
	user = _jwt_get(jinfo, "preferred_username");
	if (user == NULL)
		user = _jwt_get(jinfo, "name");
	if (user == NULL)
		user = _jwt_get(jinfo, "username");
	if (user == NULL)
		user = _jwt_get(jinfo, str_user);
	if (user == NULL || user[0] == '\0')
		user = str_anonymous;
	return user;
}

#if 0
/// unused function
const char *authz_jwt_get(const char *id_token, const char *key)
{
	const json_t *jinfo = jwt_decode_json(id_token, 0);
	if (jinfo == NULL)
		return NULL;
	if (!strcmp(key, str_user))
		return _jwt_getuser(jinfo);
	if (!strcmp(key, str_issuer))
		return _jwt_get(jinfo, "iss");
	return _jwt_get(jinfo, key);
}
#endif

int authz_jwt_getinfo(const char *id_token, const char **user, const char **issuer)
{
	const json_t *jinfo = jwt_decode_json(id_token, 0);
	if (jinfo == NULL)
		return -1;
	*user = _jwt_getuser(jinfo);
	*issuer = _jwt_get(jinfo, "iss");
	return 0;
}

static void *authz_jwt_create(http_server_t *UNUSED(server), void *arg)
{
	authz_jwt_t *ctx = NULL;
	authz_token_config_t *config = (authz_token_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;

	return ctx;
}

static int _authn_jwt_checktoken(const authz_token_config_t *config, const char *token, json_t *jinfo)
{
	int ret = EREJECT;
	if (jinfo != NULL)
	{
		if (_jwt_checkexpiration(jinfo) != ESUCCESS)
		{
			return EREJECT;
		}
		const char *issuer = _jwt_get(jinfo, "iss");
		string_t strissuer = {0};
		string_store(&strissuer, issuer, -1);
		if (issuer && string_contain(&strissuer, string_toc(&config->issuer), string_length(&config->issuer), '+'))
		{
			err("auth: token with bad issuer: %s / %s", issuer, string_toc(&config->issuer));
			return EREJECT;
		}
		ret = ESUCCESS;
	}
#ifdef AUTHZ_JWT_CHECKHEADER
	jinfo = jwt_decode_json(token, 1);
	if (jinfo != NULL)
	{
		const json_t *jtype = json_object_get(jinfo, "typ");
		if (jtype == NULL || !json_is_string(jtype) || strncmp(json_string_value(jtype), "JWT", 3))
		{
			err("auth: token is not jwt");
			json_decref(jinfo);
			ret = EREJECT;
		}
		const json_t *jalg = json_object_get(jinfo, "alg");
		if (jalg == NULL || !json_is_string(jalg) || strncmp(json_string_value(jalg), "HS256", 3))
		{
			err("auth: jwt support only Hmac sha256");
			json_decref(jinfo);
			ret = EREJECT;
		}
	}
	else
		ret = EREJECT;
#endif
	return ret;
}

int authn_jwt_checktoken(const authz_token_config_t *config, const char *token)
{
	json_t *jinfo = jwt_decode_json(token, 0);
	int ret = _authn_jwt_checktoken(config, token, jinfo);
	json_decref(jinfo);
	return ret;
}

static const char *authz_jwt_check(void *arg, const char *UNUSED(user), const char *UNUSED(passwd), const char *token)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	json_t *jinfo = jwt_decode_json(token, 0);
	if (_authn_jwt_checktoken(ctx->config, token, jinfo) == ESUCCESS)
	{
		ctx->token = token;
		return _jwt_getuser(jinfo);
	}
	json_decref(jinfo);
	return NULL;
}

static int authz_jwt_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	if (token == NULL)
		token = ctx->token;
	json_t *jinfo = jwt_decode_json(token, 0);
	if (jinfo == NULL)
		return EREJECT;

	const json_t *jhome = json_object_get(jinfo, str_home);
	if (jhome && json_is_string(jhome))
	{
		cb(cbarg, STRING_REF(str_home), json_string_value(jhome), -1);
	}

	const json_t *jroles = json_object_get(jinfo, "roles");
	if (jroles && json_is_string(jroles))
	{
		cb(cbarg, STRING_REF(str_group), json_string_value(jroles), -1);
	}
	else if (jroles && json_is_array(jroles))
	{
		cb(cbarg, STRING_REF(str_group), json_string_value(json_array_get(jroles, 0)), -1);
	}
	else
	{
		cb(cbarg, STRING_REF(str_group), STRING_REF(str_anonymous));
	}
	const json_t *jstatus = json_object_get(jinfo, str_status);
	if (jstatus && json_is_string(jstatus))
	{
		cb(cbarg, STRING_REF(str_status), json_string_value(jstatus), -1);
	}
	cb(cbarg, STRING_REF(str_user), _jwt_getuser(jinfo), -1);

	const json_t *jexpire = json_object_get(jinfo, "exp");
	if (jexpire && json_is_integer(jexpire))
	{
		time_t expire = json_integer_value(jexpire);
		struct tm *tmp;
		char expire_str[16] = {0};
		tmp = localtime(&expire);
		size_t length = strftime(expire_str, sizeof(expire_str), "%s", tmp);
		if (length > 0)
			cb(cbarg, STRING_REF("expire"), expire_str, length);
	}

	json_decref(jinfo);

	return ESUCCESS;
}

#ifdef AUTH_TOKEN
static int authz_jwt_join(void *arg, const char *user, const char *UNUSED(token), int expire)
{
	return ESUCCESS;
}
#else
#define authz_jwt_join NULL
#endif

static void authz_jwt_destroy(void *arg)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_jwt_rules =
{
	.create = &authz_jwt_create,
	.check = &authz_jwt_check,
	.passwd = NULL,
	.setsession = &authz_jwt_setsession,
	.join = &authz_jwt_join,
	.destroy = &authz_jwt_destroy,
};
