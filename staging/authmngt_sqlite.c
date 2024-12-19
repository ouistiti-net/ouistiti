/*****************************************************************************
 * authmngt_sqlite.c: Check Authentication on passwd file
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2023-2025
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
#include <sqlite3.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "mod_authmngt.h"
#include "authz_sqlite.h"
#include "authmngt_sqlite.h"

#define auth_dbg(...)

static void *authmngt_sqlite_create(http_client_t *UNUSED(client), void *arg)
{
	authz_sqlite_t *ctx = NULL;
	authz_sqlite_config_t *config = (authz_sqlite_config_t *)arg;
	int ret;
	sqlite3 *db;

	if (access(config->dbname, W_OK))
	{
		err("authmngt: auth must support sqlite DB");
		return NULL;
	}

	ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
	if (ret != SQLITE_OK)
	{
		err("authmngt: database %s error: %s", config->dbname, sqlite3_errstr(ret));
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	ctx->db = db;
	ctx->config = config;
	return ctx;
}

static void authmngt_sqlite_destroy(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	if (ctx->statement)
		sqlite3_finalize(ctx->statement);
	sqlite3_close_v2(ctx->db);
	free(ctx);
}

static int authz_sqlite_updatefield(authz_sqlite_t *ctx, int userid, const char *field, int length, int group)
{
	int ret;
	const char *sql[] = {
		"update users set name=@FIELD where id=@USERID",
		"update users set groupid=@FIELDID where id=@USERID",
		"update users set statusid=@FIELDID where id=@USERID",
		"update users set passwd=@FIELD where id=@USERID",
		"update users set home=@FIELD where id=@USERID",
		NULL,
	};

	if (sql[group] == NULL)
		return EREJECT;

	sqlite3_stmt *statement; /// use a specific statement because name may come from ctx->statement
	ret = sqlite3_prepare_v2(ctx->db, sql[group], -1, &statement, NULL);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	int fieldid = authz_sqlite_getid(ctx, field, -1, group);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	if (index > 0)
		ret = sqlite3_bind_int(statement, index, userid);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	index = sqlite3_bind_parameter_index(statement, "@FIELD");
	if (index > 0)
		ret = sqlite3_bind_text(statement, index, field, length, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	index = sqlite3_bind_parameter_index(statement, "@FIELDID");
	if (index > 0)
	{
		if (fieldid >= 0)
			ret = sqlite3_bind_int(statement, index, fieldid);
		else
			ret = SQLITE_ABORT;
	}
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sqlite3_expanded_sql(statement), sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret == SQLITE_DONE)
	{
		auth_dbg("auth: change %d to %s", group, field);
		return ESUCCESS;
	}
	err("auth: changing error on %d", group);
	return EREJECT;
}

static int _authz_store_toauth(void *arg, const char *key, size_t keylen, const char *value, size_t valuelen)
{
	if (! strcmp(key, "user"))
		snprintf(((authsession_t*)arg)->user, USER_MAX, "%s", value);
	if (! strcmp(key, "group"))
		snprintf(((authsession_t*)arg)->group, FIELD_MAX, "%s", value);
	if (! strcmp(key, "home"))
		snprintf(((authsession_t*)arg)->home, PATH_MAX, "%s", value);
	if (! strcmp(key, "status"))
		snprintf(((authsession_t*)arg)->status, FIELD_MAX, "%s", value);
	return ESUCCESS;
}

static int authz_sqlite_setsessionmng(void *arg, const char *user, authsession_t *info)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	return authz_sqlite_getuser_byName(ctx, user, _authz_store_toauth, info);
}

static int authz_sqlite_getusermng(void *arg, int id, authsession_t *info)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	return authz_sqlite_getuser_byID(ctx, id, _authz_store_toauth, info);
}

static int authz_sqlite_adduser(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	if (authz_sqlite_getid(ctx, authinfo->user, -1, FIELD_NAME) != EREJECT)
		return ESUCCESS;
	// force the first status to approving
	strncpy(authinfo->status, str_status_approving, FIELD_MAX);

	int ret;
	const char *sql = "insert into users (\"name\",\"passwd\",\"groupid\",\"statusid\",\"home\")"
			"values (@NAME,@PASSWD,@GROUPID,(select id from status where name=@STATUS),@HOME);";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	ret = sqlite3_bind_text(statement, index, authinfo->user, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@PASSWD");
	if (authinfo->passwd[0] != '\0')
	{
		ret = sqlite3_bind_text(statement, index, authinfo->passwd, -1, SQLITE_STATIC);
	}
	else
		ret = sqlite3_bind_text(statement, index, "*", -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@HOME");
	ret = sqlite3_bind_text(statement, index, authinfo->home, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@GROUPID");
	ret = sqlite3_bind_int(statement, index, DEFAULT_GROUPID);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@STATUS");
	ret = sqlite3_bind_text(statement, index, authinfo->status, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
		err("auth: add user error %d %s", ret, sqlite3_errmsg(ctx->db));
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static int authz_sqlite_addgroup(void *arg, const char *group, int length)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int ret;
	const char *sql = "insert into groups (\"name\")"
			"values (@NAME);";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	ret = sqlite3_bind_text(statement, index, group, length, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
		err("auth: add group error %d %s", ret, sqlite3_errmsg(ctx->db));
	if (ret == SQLITE_DONE)
		return sqlite3_last_insert_rowid(ctx->db);
	return EREJECT;
}

static int _compute_passwd(const hash_t *hash, const char *input, char *output, int outlen)
{
	if (input == NULL)
		return -1;

	char *hashpasswd = malloc(hash->size);
	void *ctx;
	ctx = hash->init();
	hash->update(ctx, input, strlen(input));
	hash->finish(ctx, hashpasswd);

	int len = snprintf(output, outlen, "$%c$", hash->nameid);
	len += base64->encode(hashpasswd, hash->size, output + len, outlen - len);
	free(hashpasswd);
	return len;
}

static int authz_sqlite_changepasswd(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;
	int ret = EREJECT;

	userid = authz_sqlite_getid(ctx, authinfo->user, -1, FIELD_NAME);
	if (userid == EREJECT)
		return ret;

	if (authinfo->passwd[0] != '\0')
	{
		int length = -1;
		const char *passwd = authinfo->passwd;
		char passwdarray[TOKEN_MAX];
		if (ctx->config->hash != NULL)
		{
			int len = _compute_passwd(ctx->config->hash, authinfo->passwd, passwdarray, TOKEN_MAX);
			if (len > 0)
			{
				length = len;
				passwd = passwdarray;
			}
		}

		ret = authz_sqlite_updatefield(ctx, userid, passwd, length, FIELD_PASSWD);
	}
	if (ret != EREJECT)
		ret = authz_sqlite_getusermng(ctx, userid, authinfo);

	return ret;
}

static int authz_sqlite_changeinfo(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;
	int ret = ESUCCESS;

	userid = authz_sqlite_getid(ctx, authinfo->user, -1, FIELD_NAME);
	if (userid == EREJECT)
		return EREJECT;

	if (ret == ESUCCESS && authinfo->group[0] != '\0')
	{
		int length = -1;
		const char *group = authinfo->group;
		const char *end = strchr(group, ',');
		if (end)
			length = end - group;
		int groupid = authz_sqlite_getid(ctx, group, length, FIELD_GROUP);
		if (groupid == EREJECT)
		{
			groupid = authz_sqlite_addgroup(ctx, group, length);
		}
		if (groupid != EREJECT)
			ret = authz_sqlite_updatefield(ctx, userid, group, length, FIELD_GROUP);
	}

	if (ret == ESUCCESS && authinfo->status[0] != '\0')
	{
		int statusid = authz_sqlite_getid(ctx, authinfo->status, -1, FIELD_STATUS);
		if (statusid == -1)
			err("authmngt: update unknown status %s", authinfo->status);
		else
			ret = authz_sqlite_updatefield(ctx, userid, authinfo->status, -1, FIELD_STATUS);
	}

	if (ret == ESUCCESS && authinfo->home[0] != '\0')
	{
		ret = authz_sqlite_updatefield(ctx, userid, authinfo->home, -1, FIELD_HOME);
	}

	return ret;
}

static int authz_sqlite_removeuser(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;

	userid = authz_sqlite_getid(ctx, authinfo->user, -1, FIELD_NAME);
	if (userid == EREJECT)
		return EREJECT;

	int ret;
	const char *sql = "delete from users where id=@USERID;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
	{
		err("auth: remove user error %s", sqlite3_errmsg(ctx->db));
		strncpy(authinfo->status, sqlite3_errmsg(ctx->db), FIELD_MAX);
	}
	else
		strncpy(authinfo->status, "removed", FIELD_MAX);
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static size_t authmngt_sqlite_issuer(void *arg, const char *user, char *issuer, size_t length)
{
	return authz_sqlite_issuer(arg, user, issuer, length);
}

static int authmngt_sqlite_addissuer(void *arg, int userid, const char *issuer, size_t length, int insert)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int ret;
	const char *sql = NULL;
	if (insert)
		sql = "insert into issuers (\"userid\",\"issuer\") values (@USERID,@ISSUER);";
	else
		sql = "update issuers set issuer=@ISSUER where userid=@USERID;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@ISSUER");
	ret = sqlite3_bind_text(statement, index, issuer, length, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);

	if (ret != SQLITE_DONE)
	{
		err("authmngt: impossible to change issuer");
	}
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static int authmngt_sqlite_setissuer(void *arg, const char * user, const char *issuer, size_t length)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;

	userid = authz_sqlite_getid(ctx, user, -1, FIELD_NAME);
	if (userid == EREJECT)
		return EREJECT;

	int ret;
	const char *sql = "select issuer from issuers where userid=@USERID;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);

	if (ret != SQLITE_ROW)
		ret = authmngt_sqlite_addissuer(arg, userid, issuer, length, 1);
	else
		ret = authmngt_sqlite_addissuer(arg, userid, issuer, length, 0);
	return ret;
}

authmngt_rules_t authmngt_sqlite_rules =
{
	.create = &authmngt_sqlite_create,
	.setsession = &authz_sqlite_setsessionmng,
	.getuser = &authz_sqlite_getusermng,
	.adduser = &authz_sqlite_adduser,
	.changepasswd = &authz_sqlite_changepasswd,
	.changeinfo = &authz_sqlite_changeinfo,
	.removeuser = &authz_sqlite_removeuser,
	.issuer = &authmngt_sqlite_issuer,
	.setissuer = &authmngt_sqlite_setissuer,
	.destroy = &authmngt_sqlite_destroy,
};
