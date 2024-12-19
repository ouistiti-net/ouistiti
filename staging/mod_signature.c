/*****************************************************************************
 * mod_signature.c: rfc9421
 *****************************************************************************
 * Copyright (C) 2024-2027
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

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/utils.h"
#include "mod_document.h"
#include "ouistiti.h"

static const char str_signature[] = "Signature";
static const char str_signature_input[] = "Signature-Input";

typedef struct mod_signature_s mod_signature_t;
struct mod_signature_s
{
	uint32_t fields;
	const char *alg;
	string_t key;
	htaccess_t htaccess;
};

typedef struct signature_element_s signature_element_t;
struct signature_element_s
{
	string_t component;
	string_t field;
};

static signature_element_t _default_elemts[] =
{
	{
		.component = STRING_DCL("content-type"),
		.field = STRING_DCL("Content-Type"),
	},
	{
		.component = STRING_DCL("content-length"),
		.field = STRING_DCL("Content-Length"),
	},
	{
		.component = STRING_DCL("content-digest"),
		.field = STRING_DCL("Content-Digest"),
	},
	{
		.component = STRING_DCL("@status"),
		.field = STRING_DCL("status"),
	},
};

typedef struct _mod_signature_s _mod_signature_t;
struct _mod_signature_s
{
	http_server_t *server;
	mod_signature_t *config;
	const hash_t *hash;
	string_t key;
	uint32_t fields;
};

typedef struct _mod_signature_ctx_s _mod_signature_ctx_t;
struct _mod_signature_ctx_s
{
	_mod_signature_t *mod;
	int enabled;
	http_message_t *req;
};

static void *_mod_signature_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize));
static void _mod_signature_freectx(void *arg);
static int _signature_connectorcheck(void *arg, http_message_t *request, http_message_t *response);
static int _signature_connectorcomplete(void *arg, http_message_t *request, http_message_t *response);

void *mod_signature_create(http_server_t *server, mod_signature_t *config)
{
	if (config == NULL || config->fields == 0)
		return NULL;
	_mod_signature_t *mod = calloc(1, sizeof(*mod));
	mod->server = server;
	mod->config = config;
	mod->fields = config->fields;
	mod->hash = hash_macsha256;
	string_store(&mod->key, config->key.data, config->key.length);
	httpserver_addmod(server, _mod_signature_getctx, _mod_signature_freectx, mod, str_signature);
	return mod;
}

void mod_signature_destroy(void *arg)
{
	_mod_signature_t *mod = (_mod_signature_t *)arg;
	free(mod->config);
	free(mod);
}

static void *_mod_signature_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	_mod_signature_t *mod = (_mod_signature_t *)arg;
	_mod_signature_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	httpclient_addconnector(clt, _signature_connectorcheck, ctx, CONNECTOR_DOCFILTER, str_signature);
	httpclient_addconnector(clt, _signature_connectorcomplete, ctx, CONNECTOR_COMPLETE, str_signature);
	return ctx;
}

static void _mod_signature_freectx(void *arg)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	free(ctx);
}

static int _signature_connectorcheck(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	_mod_signature_t *mod = ctx->mod;

	const char *path_info = NULL;
	const char *uri = httpmessage_REQUEST(request, "uri");
	if (htaccess_check(&mod->config->htaccess, uri, &path_info) == ESUCCESS)
	{
		ctx->enabled = 1;
	}
	ctx->req = request;
	return EREJECT;
}

static int _signature_connectorcomplete(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	if (ctx->enabled == 0)
		return EREJECT;
	_mod_signature_t *mod = ctx->mod;
	const hash_t *hash = mod->hash;
	void *hashctx;

	/*
	 * TODO this is not the real algo of frc9530
	 * it's sujst a test
	 */
	hashctx = hash->initkey(STRING_INFO(mod->key));
	char input[256];
	char *inputoffset = input;
	*inputoffset = '(';
	inputoffset++;
	for (int i = 0; i < sizeof(_default_elemts)/ sizeof(*_default_elemts); i++)
	{
		if (mod->fields & (1<<i))
		{
			signature_element_t *elemt = &_default_elemts[i];
			const char *field = NULL;
			int len;
			len = snprintf(inputoffset, 24, "\"%.20s\" ", string_toc(&elemt->component));
			inputoffset += len;
			len = httpmessage_REQUEST2(response, string_toc(&elemt->field), &field);
			hash->update(hashctx, "\"", 1);
			hash->update(hashctx, string_toc(&elemt->component), string_length(&elemt->component));
			hash->update(hashctx, "\": ", 3);
			hash->update(hashctx, field, len);
			hash->update(hashctx, "\n", 1);
			if (inputoffset + 24 > input + sizeof(input))
				break;
		}
	}
	*inputoffset = ')';
	inputoffset++;
	hash->update(hashctx, "\"", 1);
	hash->update(hashctx, "@signature-params", 17);
	hash->update(hashctx, "\": ", 3);
	hash->update(hashctx, input, inputoffset - input);
	hash->update(hashctx, "\n", 1);
	unsigned char signature[32];
	size_t signlen = hash->finish(hashctx, signature);
	char result[((HASH_MAX_SIZE * 3) / 2 + 1)] = {0};
	base64->encode(signature, signlen, result, sizeof(result));
	httpmessage_addheader(response, str_signature_input, input, -1);
	httpmessage_addheader(response, str_signature, result, -1);
	httpmessage_appendheader(response, str_signature, ";created=", 9);
	time_t t = time(NULL);
	unsigned char tstr[24];
	int tlen = snprintf(tstr, 24, "%.23ld", t);
	httpmessage_appendheader(response, str_signature, tstr, tlen);
	httpmessage_appendheader(response, str_signature, ";alg=", 5);
	httpmessage_appendheader(response, str_signature, mod->hash->name, -1);
	dbg("signature: connector ready");
	return ESUCCESS;
}

static int _signature_add_component(mod_signature_t *signature, const char *component)
{
	int ret = -1;
	for (int i = 0; i < sizeof(_default_elemts)/ sizeof(*_default_elemts); i++)
	{
		if (! string_cmp(&_default_elemts[i].component, component, -1))
		{
			signature->fields |= (1 << i);
			break;
		}
	}
	return ret;
}
#ifdef FILE_CONFIG
static void * _signature_config(config_setting_t *config, server_t *server)
{
	mod_signature_t *signature = NULL;

	const char *key = NULL;
	config_setting_lookup_string(config, "key", &key);
	if (key != NULL && key[0] != '0')
	{
		signature = calloc(1,sizeof(*signature));

		signature->key.data = key;
		signature->key.length = strlen(signature->key.data);
		config_setting_t *components = NULL;
		components = config_setting_lookup(config, "components");
		if (components && config_setting_is_list(components))
		{
			int nbelems = 0;
			nbelems = config_setting_length(components);
			for (int i = 0; i < nbelems; i++)
			{
				config_setting_t *component = config_setting_get_elem(components, i);
				if (config_setting_type(component) ==  CONFIG_TYPE_STRING &&
					_signature_add_component(signature, config_setting_get_string(component)))
				{
					warn("signature: component %s is not supported",config_setting_get_string(component));
				}
			}
		}
		config_setting_lookup_string(config, "algorithm", &signature->alg);
		htaccess_config(config, &signature->htaccess);
	}
	return signature;
}
static void *mod_signature_config(config_setting_t *iterator, server_t *server)
{
	mod_signature_t *signature = NULL;

#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "signature");
#else
	config_setting_t *config = config_setting_lookup(iterator, "signature");
#endif
	if (config && config_setting_is_group(config))
	{
		signature = _signature_config(config, server);
	}
	return signature;
}
#else
static void *mod_signature_config(void *iterator, server_t *server)
{
	mod_signature_t *signature = NULL;

	signature = calloc(1,sizeof(*signature));
	return signature;
}
#endif

const module_t mod_signature =
{
	.name = str_signature,
	.configure = (module_configure_t)&mod_signature_config,
	.create = (module_create_t)mod_signature_create,
	.destroy = mod_signature_destroy,
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_signature")));
#endif
