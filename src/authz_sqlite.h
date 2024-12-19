/*****************************************************************************
 * authz_file.h: Check Authentication on .file file
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

#ifndef __AUTHN_SQLITE_H__
#define __AUTHN_SQLITE_H__

#include "mod_auth.h"

#define DEFAULT_GROUPID 2

#define FIELD_NAME 0
#define FIELD_GROUP 1
#define FIELD_STATUS 2
#define FIELD_PASSWD 3
#define FIELD_HOME 4

#ifdef DEBUG
#define SQLITE3_CHECK(ret, value, sql) \
	do { \
		if (ret != SQLITE_OK) { \
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql, sqlite3_errmsg(ctx->db)); \
			return value; \
		} \
	} while(0)
#else
#define SQLITE3_CHECK(...)
#endif

typedef struct authz_sqlite_config_s authz_sqlite_config_t;
struct authz_sqlite_config_s
{
	const char *dbname;
	const hash_t *hash;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_sqlite_config(const config_setting_t *configauth);
#endif

extern authz_rules_t authz_sqlite_rules;

#include <sqlite3.h>
typedef struct authz_sqlite_s authz_sqlite_t;
struct authz_sqlite_s
{
	authz_sqlite_config_t *config;
	int ref;
	sqlite3 *db;
	sqlite3 *dbjoin;
	sqlite3_stmt *statement;
	int userid;
};

typedef int (*storeinfo_t)(void *arg, const char *key, size_t keylen, const char *value, size_t valuelen);

int authz_sqlite_getid(authz_sqlite_t *ctx, const char *name, int length, int table);
int authz_sqlite_getuser_byID(authz_sqlite_t *ctx, int id, storeinfo_t callback, void *cbarg);
int authz_sqlite_getuser_byName(authz_sqlite_t *ctx, const char * user, storeinfo_t callback, void *cbarg);
size_t authz_sqlite_issuer(void *arg, const char *user, char *issuer, size_t length);

#endif
