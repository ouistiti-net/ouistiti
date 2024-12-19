/*****************************************************************************
 * authn_digest.c: Basic Authentication mode
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
#include <time.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authn_digest.h"

#define auth_dbg(...)

#define MAXNONCE 64

typedef struct authn_digest_config_s authn_digest_config_t;
typedef struct authn_digest_s authn_digest_t;
struct authn_digest_s
{
	authn_digest_config_t *config;
	const authn_t *authn;
	const hash_t *hash;
	char _nonce[MAXNONCE];
	string_t nonce;
	char *user;
	int stale;
	int encode;
};

struct authn_digest_config_s
{
	string_t opaque;
};

#ifdef FILE_CONFIG
void *authn_digest_config(const config_setting_t *configauth)
{
	authn_digest_config_t *authn_config = NULL;

	const char *opaque = NULL;
	config_setting_lookup_string(configauth, "opaque", &opaque);
	if (opaque == NULL)
	{
		err("authn Digest needs opaque value");
		return NULL;
	}

	authn_config = calloc(1, sizeof(*authn_config));
	string_store(&authn_config->opaque, opaque, -1);
	return authn_config;
}
#endif

static size_t utils_stringify(const unsigned char *data, size_t len, char **result)
{
	size_t length = 0;
	*result = calloc(2, len + 1);
	for (size_t i = 0; i < len; i++)
	{
		length += snprintf(*result + i * 2, 3, "%02x", data[i]);
	}
	return length;
}

#ifdef DEBUG
static char str_opaque_rfc7616[] = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";
static char str_nonce_rfc7616[] = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
static char str_nonce_rfc2617[] = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
#endif

static void *authn_digest_create(const authn_t *authn, void *config)
{
	if (authn->config->authn.hash == NULL)
		return NULL;
	authn_digest_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_digest_config_t *)config;
	mod->authn = authn;
	mod->hash = authn->config->authn.hash;
	string_store(&mod->nonce, mod->_nonce, 0);
#ifdef DEBUG
	err("Auth DIGEST is not secure in DEBUG mode, rebuild!!!");
	if (! string_cmp(&mod->config->opaque, STRING_REF(str_opaque_rfc7616)))
		mod->nonce.length = snprintf(STRING_REF(mod->_nonce), "%s", str_nonce_rfc7616); //RFC7616
	else
		mod->nonce.length = snprintf(STRING_REF(mod->_nonce), "%s", str_nonce_rfc2617); //RFC2617
#endif
	return mod;
}

static int authn_digest_noncetime(authn_digest_t *mod, char *nonce, size_t noncelen)
{
	int expire = 30;
	if (mod->authn->config->token.expire != 0)
		expire = mod->authn->config->token.expire;
	time_t now = time(NULL);
	now -= now % (60 * expire);
	now += (60 *expire);
	const char *key = mod->authn->config->token.secret.data;
	size_t keylen = mod->authn->config->token.secret.length;
	if (hash_macsha256 != NULL && key != NULL)
	{
		void *ctx = hash_macsha256->initkey(key, keylen);
		if (ctx)
		{
			hash_macsha256->update(ctx, (char*)&now, sizeof(now));
			char signature[HASH_MAX_SIZE];
			size_t signlen = HASH_MAX_SIZE;
			signlen = hash_macsha256->finish(ctx, signature);
#if 0
			if ((signlen * 1.5) > noncelen)
				signlen = noncelen / 1.5;
#endif
			signlen = base64_urlencoding->encode(signature, signlen, nonce, noncelen);
			return signlen;
		}
	}
	return EREJECT;
}

static int authn_digest_nonce(authn_digest_t *mod, char *nonce, size_t noncelen)
{
	int ret = EREJECT;

/**
 *  nonce and opaque may be B64 encoded data
 * or hexa encoded data
 */
#ifndef DEBUG
	char _nonce[((HASH_MAX_SIZE * 3) / 2 + 1)] = {0};

	srandom(time(NULL));
	int usedate = random() % 5;
	if (usedate)
	{
		ret = authn_digest_noncetime(mod, _nonce, sizeof(_nonce));
	}
	if (ret == EREJECT)
	{
		int i;
		for (i = 0; i < (sizeof(_nonce) / sizeof(int)); i++)
			*(int *)(_nonce + i * sizeof(int)) = random();
		ret = base64->encode(_nonce, sizeof(_nonce), nonce, noncelen);
	}
#else
	ret = mod->nonce.length;
#endif
	return ret;
}

static void * authn_digest_setup(void *arg, http_client_t *UNUSED(ctl), struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	authn_digest_t *mod = (authn_digest_t *)arg;

	mod->stale = 0;
	int length = authn_digest_nonce(arg, STRING_REF(mod->_nonce));
	if (length < 0)
		return NULL;
	mod->nonce.length = length;
	return mod;
}

static void authn_digest_www_authenticate(authn_digest_t *mod, http_message_t * response)
{
	httpmessage_addheader(response, str_authenticate, STRING_REF("Digest "));
	if (!string_empty(&mod->authn->config->realm))
	{
		httpmessage_appendheader(response, str_authenticate, STRING_REF("realm=\""));
		httpmessage_appendheader(response, str_authenticate, STRING_INFO(mod->authn->config->realm));
		httpmessage_appendheader(response, str_authenticate, STRING_REF("\""));
	}
	httpmessage_appendheader(response, str_authenticate, STRING_REF(",qop=\"auth\",nonce=\""));
	httpmessage_appendheader(response, str_authenticate, STRING_INFO(mod->nonce));
	httpmessage_appendheader(response, str_authenticate, STRING_REF("\",opaque=\""));
	httpmessage_appendheader(response, str_authenticate, STRING_INFO(mod->config->opaque));
	httpmessage_appendheader(response, str_authenticate, STRING_REF("\",stale="));
	if (mod->stale)
		httpmessage_appendheader(response, str_authenticate, STRING_REF("true"));
	else
		httpmessage_appendheader(response, str_authenticate, STRING_REF("false"));
}

static int authn_digest_challenge(void *arg, http_message_t *UNUSED(request), http_message_t *response)
{
	int ret;
	authn_digest_t *mod = (authn_digest_t *)arg;

	/**
	 * WWW-AUTHENTICATE header without algorithm is mandatory
	 * Firefox and Chrome doesn't support other algorithm than MD5
	 */
	authn_digest_www_authenticate(mod, response);

	if (mod->hash != hash_md5)
	{
		httpmessage_appendheader(response, str_authenticate, STRING_REF(",algorithm="));
		httpmessage_appendheader(response, str_authenticate, mod->hash->name, -1);
	}

#ifdef DEBUG
	char _nonce[(int)(HASH_MAX_SIZE * 1.5) + 1];
	int length = authn_digest_noncetime(arg, _nonce, sizeof(_nonce));
	if (length > 0)
		httpmessage_addheader(response, "test-nonce-time", _nonce, length);
#endif

	httpmessage_keepalive(response);
	ret = ECONTINUE;
	return ret;
}

struct authn_digest_computing_s
{
	char *(*digest)(const hash_t * hash, const char *a1, size_t a1len, const char *nonce, size_t noncelen, const char *nc, size_t nclen, const char *cnonce, size_t cnoncelen, const char *qop, size_t qoplen, const char *a2, size_t a2len);
	size_t (*a1)(const hash_t * hash, const char *user, size_t userlen, const char *realm, size_t realmlen, const char *passwd, size_t passwdlen, char **a1);
	size_t (*a2)(const hash_t * hash, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *entity, size_t entitylen, char **a2);
};

static char *authn_digest_digest(const hash_t * hash, const char *a1, size_t a1len, const char *nonce, size_t noncelen, const char *nc, size_t nclen, const char *cnonce, size_t cnoncelen, const char *qop, size_t qoplen, const char *a2, size_t a2len)
{
	if (a1 && a2)
	{
		unsigned char digest[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, a1, a1len);
		hash->update(ctx, ":", 1);
		hash->update(ctx, nonce, noncelen);
		if (qop && !strncmp(qop, "auth", qoplen))
		{
			if (nc)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, nc, nclen);
			}
			if (cnonce)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, cnonce, cnoncelen);
			}
			hash->update(ctx, ":", 1);
			hash->update(ctx, qop, qoplen);
		}
		hash->update(ctx, ":", 1);
		hash->update(ctx, a2, a2len);
		hash->finish(ctx, digest);
		char *result = NULL;
#ifdef AUTH_DEBUG
		for (int i = 0; i < sizeof(digest); i++)
			fprintf(stderr, "%X", digest[i]);
		fprintf(stderr,"\n");
#endif
		utils_stringify(digest, hash->size, &result);
		return result;
	}
	return NULL;
}

static size_t authn_digest_a1(const hash_t * hash, const char *user, size_t userlen, const char *realm, size_t realmlen, const char *passwd, size_t passwdlen, char **a1)
{
	if (passwd[0] != '$')
	{
		unsigned char A1[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, user, userlen);
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm, realmlen);
		hash->update(ctx, ":", 1);
		hash->update(ctx, passwd, passwdlen);
		hash->finish(ctx, A1);
		return utils_stringify(A1, hash->size, a1);
	}
	else if (passwd[0] == '$')
	{
		const char *fullpasswd = passwd;
		int i = 1;
		int decode = 0;
		if (passwd[i] == 'a')
		{
			decode = 1;
			i++;
		}
		if (passwd[i] == 'd')
		{
			i++;
		}
		if ( passwd[i] == hash->nameid)
		{
			passwd = strrchr(passwd + 1, '$');
			passwd += 1;
			if (decode)
			{
				unsigned char b64passwd[64] = {0};
				passwdlen -= passwd - fullpasswd;
				int len = base64->decode(passwd, passwdlen, b64passwd, 64);
				return utils_stringify(b64passwd, len, a1);
			}
			*a1 = strdup(passwd);
			return passwdlen;
		}
	}
	return 0;
}

static size_t authn_digest_a2(const hash_t * hash, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *entity, size_t entitylen, char **a2)
{
	unsigned char A2[32];
	void *ctx;

	ctx = hash->init();
	hash->update(ctx, method, methodlen);
	hash->update(ctx, ":", 1);
	hash->update(ctx, uri, urilen);
	if (entity)
	{
		hash->update(ctx, ":", 1);
		hash->update(ctx, entity, entitylen);
	}
	hash->finish(ctx, A2);
	return utils_stringify(A2, hash->size, a2);
}
static struct authn_digest_computing_s *authn_digest_computing = &(struct authn_digest_computing_s)
{
	.digest = authn_digest_digest,
	.a1 = authn_digest_a1,
	.a2 = authn_digest_a2,
};

struct checkuri_s
{
	authn_digest_t *mod;
	const char *url;
	const char *value;
	size_t length;
};
typedef struct checkuri_s checkuri_t;

static int authn_digest_checkuri(void *data, const char *uri, size_t urilen)
{
	checkuri_t *info = (checkuri_t *)data;

	if (uri != NULL)
	{
		if (!strncmp(info->url, uri, urilen))
		{
			info->value = uri;
			info->length = urilen;
			auth_dbg("uri %.*s", (int)info->length, info->value);
			return ESUCCESS;
		}
		warn("try connection on %s with authorization on %s", info->url, uri);
	}
	else
		warn("auth: uri is unset");
	return EREJECT;
}

struct chekcalgorithm_s
{
	authn_digest_t *mod;
	const hash_t *hash;
};
typedef struct chekcalgorithm_s chekcalgorithm_t;

static int authn_digest_checkalgorithm(void *data, const char *algorithm, size_t algorithmlen)
{
	chekcalgorithm_t *info = (chekcalgorithm_t *)data;
	const authn_digest_t *mod = info->mod;

	info->hash = hash_md5;

	if (algorithm != NULL)
	{
		/**
		 * Firefox and Chrome doesn't support other algorithm than MD5
		 * https://bugzilla.mozilla.org/show_bug.cgi?id=472823
		 */
		if(!strncmp(algorithm, mod->hash->name, algorithmlen))
		{
			info->hash = mod->hash;
		}
		else
		{
			warn("auth: algorithm is bad %s/%s", algorithm, mod->hash->name);
			return EREJECT;
		}
	}
	auth_dbg("algorithm %s", info->hash->name);
	return ESUCCESS;
}

struct checkstring_s
{
	authn_digest_t *mod;
	const char *value;
	size_t length;
};
typedef struct checkstring_s checkstring_t;
static int authn_digest_checkrealm(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;
	const authn_digest_t *mod = info->mod;

	if (value != NULL && !string_cmp(&mod->authn->config->realm, value, length))
	{
		info->value = value;
		info->length = length;
		auth_dbg("realm %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: realm is unset or bad");
	return EREJECT;
}

static int authn_digest_checknonce(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;
	authn_digest_t *mod = info->mod;

	if (value != NULL && !string_cmp(&mod->nonce, value, length))
	{
		info->value = value;
		info->length = length;
		auth_dbg("nonce %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: nonce is unset or bad");
	mod->stale++;
	mod->stale %= 5;
	return EREJECT;
}

static int authn_digest_checkopaque(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;
	const authn_digest_t *mod = info->mod;

	if (value != NULL && !string_cmp(&mod->config->opaque, value, length))
	{
		info->value = value;
		info->length = length;
		auth_dbg("opaque %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: opaque is unset");
	return ECONTINUE;
}

static int authn_digest_checkcnonce(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;

	if (value != NULL)
	{
		info->value = value;
		info->length = length;
		auth_dbg("cnonce %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: cnonce is unset");
	return ESUCCESS;
}

static int authn_digest_checkqop(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;

	if (value != NULL)
	{
		info->value = value;
		info->length = length;
		auth_dbg("qop %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: qop is unset");
	return EREJECT;
}

static int authn_digest_checknc(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;
	authn_digest_t *mod = info->mod;

	if (value != NULL)
	{
		long nc = strtol(value, NULL, 10);
		if (nc < 5)
		{
			info->value = value;
			info->length = length;
			auth_dbg("nc %.*s", (int)length, value);
			return ESUCCESS;
		}
		mod->stale = 0;
		return EREJECT;
	}
	warn("auth: nc is unset");
	return ESUCCESS;
}

static int authn_digest_checkresponse(void *data, const char *value, size_t length)
{
	checkstring_t *info = (checkstring_t *)data;

	if (value != NULL)
	{
		info->value = value;
		info->length = length;
		auth_dbg("response %.*s", (int)length, value);
		return ESUCCESS;
	}
	warn("auth: response is unset");
	return EREJECT;
}

struct checkuser_s
{
	authz_t *authz;
	const char *value;
	size_t length;
	const char *passwd;
	size_t passwdlen;
};

typedef struct checkuser_s checkuser_t;
static int authn_digest_checkuser(void *data, const char *user, size_t length)
{
	checkuser_t *info = (checkuser_t *)data;
	authz_t *authz = info->authz;

	if (user != NULL)
	{
		info->passwdlen = authz->rules->passwd(authz->ctx, user, &info->passwd);
		if (info->passwdlen > 0)
		{
			info->value = user;
			info->length = length;
			auth_dbg("user %.*s", (int)length, user);
			return ESUCCESS;
		}
		warn("auth: user %s is unknown", user);
	}
	warn("auth: user is unset");
	return EREJECT;
}


static char *str_empty = "";
static const char *authn_digest_check(void *arg, authz_t *authz, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *string, size_t stringlen)
{
	const char *user_ret = NULL;
	authn_digest_t *mod = (authn_digest_t *)arg;
	checkuri_t url = { .mod = mod, .url = uri};
	chekcalgorithm_t algorithm = { .mod = mod};
	checkuser_t user = {.authz = authz};
	checkstring_t realm = {.mod = mod, .value = str_empty, .length = 0};
	checkstring_t qop = {.mod = mod};
	checkstring_t nonce = {.mod = mod};
	checkstring_t cnonce = {.mod = mod, .value = str_empty, .length = 0};
	checkstring_t nc = {.mod = mod};
	checkstring_t opaque = {.mod = mod, .value = str_empty, .length = 0};
	checkstring_t response = {.mod = mod};
	utils_parsestring_t parser[] = {
		{.field = "username", .cb = authn_digest_checkuser, .cbdata = &user},
		{.field = "response", .cb = authn_digest_checkresponse, .cbdata = &response},
		{.field = "uri", .cb = authn_digest_checkuri, .cbdata = &url},
		{.field = "algorithm", .cb = authn_digest_checkalgorithm, .cbdata = &algorithm},
		{.field = "realm", .cb = authn_digest_checkrealm, .cbdata = &realm},
		{.field = "qop", .cb = authn_digest_checkqop, .cbdata = &qop},
		{.field = "nonce", .cb = authn_digest_checknonce,.cbdata =  &nonce},
		{.field = "cnonce", .cb = authn_digest_checkcnonce,.cbdata =  &cnonce},
		{.field = "nc", .cb = authn_digest_checknc, .cbdata = &nc},
		{.field = "opaque", .cb = authn_digest_checkopaque, .cbdata = &opaque},
	};

	int ret = utils_parsestring(string, stringlen, 10, parser);
	if (ret == ESUCCESS && authn_digest_computing)
	{
		char *a1 = NULL;
		size_t a1len = authn_digest_computing->a1(algorithm.hash,
						user.value, user.length,
						realm.value, realm.length,
						user.passwd, user.passwdlen, &a1);
		auth_dbg("a1:\n\t%.*s\n", (int)a1len, a1);
		char *a2 = NULL;
		size_t a2len = authn_digest_computing->a2(algorithm.hash,
						method, methodlen,
						url.value, url.length,
						NULL, 0, &a2);
		auth_dbg("a2:\n\t%.*s\n", (int)a2len, a2);
		char *digest = authn_digest_computing->digest(algorithm.hash,
						a1, a1len,
						nonce.value, nonce.length,
						nc.value, nc.length,
						cnonce.value, cnonce.length,
						qop.value, qop.length,
						a2, a2len);

		auth_dbg("Digest:\n\t%.*s\n\t%s", (int)response.length, response.value, digest);
		if (mod->user != NULL)
			free(mod->user);
		if (digest && !strncmp(digest, response.value, response.length))
		{
			mod->user = strndup(user.value, user.length);
			user_ret = mod->user;
		}
		else
			mod->user = NULL;
		free (a1);
		free (a2);
		free (digest);
	}
	return user_ret;
}

static void authn_digest_destroy(void *arg)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	if (mod->user != NULL)
		free(mod->user);
	free(mod->config);
	free(mod);
}

authn_rules_t authn_digest_rules =
{
	.create = &authn_digest_create,
	.setup = &authn_digest_setup,
	.challenge = &authn_digest_challenge,
	.check = &authn_digest_check,
	.destroy = &authn_digest_destroy,
};
