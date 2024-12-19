/*****************************************************************************
 * mod_auth.h: HTTP Authentication module
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
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

#ifndef __MOD_AUTH_H__
#define __MOD_AUTH_H__

#include <linux/limits.h>

#include "ouistiti.h"

#ifdef __cplusplus
extern "C"
{
#endif
extern const char *str_authenticate_engine[];

typedef struct mod_auth_s mod_auth_t;

#define USER_MAX 64
#define FIELD_MAX 32
#define TOKEN_MAX 123

typedef int (*auth_saveinfo_t)(void *arg, const char *key, size_t keylen, const char *value, size_t valuelen);

typedef void *(*authz_rule_create_t)(http_server_t *server, void *config);
typedef void *(*authz_rule_setup_t)(void *arg);
typedef const char *(*authz_rule_check_t)(void *arg, const char *user, const char *passwd, const char *token);
typedef const int (*authz_rule_join_t)(void *arg, const char *user, const char *token, int expire);
typedef int (*authz_rule_passwd_t)(void *arg, const char *user, const char **passwd);
/**
 * @brief returns *disabled* issuers of the current user
 */
typedef size_t (*authz_rule_issuer_t)(void *arg, const char *user, char *issuer, size_t length);
typedef int (*authz_rule_setsession_t)(void* arg, const char *user, const char *toke, auth_saveinfo_t cb, void *cbarg);
typedef void (*authz_rule_cleanup_t)(void *arg);
typedef void (*authz_rule_destroy_t)(void *arg);
typedef struct authz_rules_s authz_rules_t;
struct authz_rules_s
{
	authz_rule_create_t create;
	authz_rule_setup_t setup;
	authz_rule_check_t check;
	authz_rule_join_t join;
	authz_rule_passwd_t passwd;
	authz_rule_issuer_t issuer;
	authz_rule_setsession_t setsession;
	authz_rule_cleanup_t cleanup;
	authz_rule_destroy_t destroy;
};
typedef enum
{
	AUTHZ_SIMPLE_E = 1,
	AUTHZ_FILE_E,
	AUTHZ_UNIX_E,
	AUTHZ_SQLITE_E,
	AUTHZ_JWT_E,
	AUTHZ_TOTP_E,
	AUTHZ_TYPE_MASK = 0x0F,
	AUTHZ_HOME_E = 0x10,
	AUTHZ_TOKEN_E = 0x80,
	AUTHZ_CHOWN_E = 0x100,
	AUTHZ_TLS_E = 0x200,
} authz_type_t;
typedef struct authz_s authz_t;
struct authz_s
{
	void *ctx;
	authz_rules_t *rules;
	authz_type_t type;
	string_t name;
};

struct mod_authz_s
{
	void *config;
	authz_type_t type;
	string_t name;
};
typedef struct mod_authz_s mod_authz_t;

typedef struct authn_s authn_t;
typedef void *(*authn_rule_create_t)(const authn_t *authn, void *config);
typedef void *(*authn_rule_setup_t)(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
typedef void (*authn_rule_cleanup_t)(void *arg);
typedef int (*authn_rule_challenge_t)(void *arg, http_message_t *request, http_message_t *response);
typedef const char *(*authn_rule_check_t)(void *arg, authz_t *authz, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *string, size_t stringlen);
typedef const char *(*authn_rule_checkrequest_t)(void *arg, authz_t *authz, http_message_t *request);
typedef void (*authn_rule_destroy_t)(void *arg);
typedef struct authn_rules_s authn_rules_t;
struct authn_rules_s
{
	authn_rule_create_t create;
	authn_rule_setup_t setup;
	authn_rule_cleanup_t cleanup;
	authn_rule_challenge_t challenge;
	authn_rule_check_t check;
	authn_rule_checkrequest_t checkrequest;
	authn_rule_destroy_t destroy;
};
typedef enum
{
	AUTHN_FORBIDDEN_E = -1,
	AUTHN_NONE_E = 0,
	AUTHN_BASIC_E = 1,
	AUTHN_DIGEST_E,
	AUTHN_BEARER_E,
	AUTHN_OAUTH2_E,
	AUTHN_WWWFORM_E,
	AUTHN_TYPE_MASK = 0x0F,
	AUTHN_REDIRECT_E = 0x10,
	AUTHN_COOKIE_E = 0x20,
	AUTHN_HEADER_E = 0x40,
	AUTHN_TOKEN_E = 0x80,
} authn_type_t;

typedef struct hash_s hash_t;

struct authn_s
{
	void *ctx;
	authn_rules_t *rules;
	authn_type_t type;
	http_server_t *server;
	mod_auth_t *config;
};

struct mod_authn_s
{
	void *config;
	authn_type_t type;
	string_t name;
	const hash_t *hash;
};
typedef struct mod_authn_s mod_authn_t;

typedef size_t (*authz_rule_generatetoken_t)(void* arg, http_message_t *request, char **token);
typedef struct authz_token_config_s authz_token_config_t;
struct authz_token_config_s
{
	enum {
		E_OUITOKEN,
		E_JWT,
	}type;
	string_t secret;
	string_t issuer;
	unsigned int expire;
};

struct mod_auth_s
{
	mod_authn_t authn;
	mod_authz_t authz;
	authz_token_config_t token;
	string_t algo;
	string_t redirect;
	string_t token_ep;
	string_t realm;
	const char *protect;
	const char *unprotect;
};

extern const module_t mod_auth;

int authz_checkpasswd(const char *checkpasswd, const string_t *user,
		const string_t *realm, const string_t *passwd);
int authn_checksignature(const char *key, size_t keylen,
		const char *data, size_t datalen,
		const char *sign, size_t signlen);

const char *auth_info(http_message_t *request, const char *key, size_t keylen);
size_t auth_info2(http_message_t *request, const char *key, const char **value);

#ifdef __cplusplus
}
#endif

#endif
