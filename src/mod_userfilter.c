/*****************************************************************************
 * mod_userfilter.c: callbacks and management of request method
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sqlite3.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "mod_userfilter.h"

#define userfilter_dbg(...)

#define SQLITE3_CHECK(ret, value, sql) \
	do { \
		if (ret != SQLITE_OK) {\
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql, sqlite3_errmsg(ctx->db)); \
			sqlite3_finalize(statement); \
			return value; \
		} \
	} while (0)

static const char str_userfilter[] = "userfilter";
static const char str_superuser[] = "root";
static const char str_userfilterpath[] = SYSCONFDIR"/userfilter.db";

typedef struct _mod_userfilter_s _mod_userfilter_t;

typedef int (*cmp_t)(_mod_userfilter_t *mod, const char *value,
				const char *user, const char *group, const char *home,
				const char *uri);

struct _mod_userfilter_s
{
	sqlite3 *db;
	cmp_t cmp;
	mod_userfilter_t *config;
	int line;
};

int _exp_cmp(_mod_userfilter_t *UNUSED(ctx), const char *value,
				const char *user, const char *group, const char *home,
				const char *uri)
{
	int ret = EREJECT;
	const char *entries[3] = {0};
	int nbentries = 0;

	char *valuefree = strdup(value);
	char *p = strchr(valuefree, '%');
	while (p != NULL)
	{
		p++;
		switch (*p)
		{
			case 'u':
				*p = 's';
				entries[nbentries] = user;
				nbentries++;
			break;
			case 'g':
				*p = 's';
				entries[nbentries] = group;
				nbentries++;
			break;
			case 'h':
				*p = 's';
				entries[nbentries] = home;
				nbentries++;
			break;
			default:
				free(valuefree);
				return ret;
		}
		p = strchr(p, '%');
		if (nbentries >= 3)
			break;
	}
	char *checking;
	if (asprintf(&checking, valuefree, entries[0], entries[1], entries[2]) < 0)
	{
		free(valuefree);
		return EREJECT;
	}
	userfilter_dbg("userfilter: check %s %s", uri, checking);
	if (utils_searchexp(uri, checking, NULL) == ESUCCESS)
		ret = ESUCCESS;
	free(valuefree);
	free(checking);
	return ret;
}

static int64_t _search_field(_mod_userfilter_t *ctx, int ifield, const char *value, int length)
{
	int64_t ret = EREJECT;
	int step;
	sqlite3_stmt *statement;
	const char *sql[] = {
		"select id from methods where name=@VALUE;",
		"select id from roles where name=@VALUE;",
	};
	step = sqlite3_prepare_v2(ctx->db, sql[ifield], -1, &statement, NULL);
	SQLITE3_CHECK(step, EREJECT, sql[ifield]);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@VALUE");
	step = sqlite3_bind_text(statement, index, value, length, SQLITE_STATIC);
	SQLITE3_CHECK(step, EREJECT, sql[ifield]);

	step = sqlite3_step(statement);
	if (step == SQLITE_ROW)
	{
		ret = sqlite3_column_int(statement,0);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int64_t _search_method(_mod_userfilter_t *ctx, const char *method, int length)
{
	return _search_field(ctx, 0, method, length);
}

static int64_t _search_role(_mod_userfilter_t *ctx, const char *role, int length)
{
	return _search_field(ctx, 1, role, length);
}

static int _request(_mod_userfilter_t *ctx, const char *method,
				const char *user, const char *group, const char *home,
				const char *uri)
{
	int ret = EREJECT;
	int64_t methodid = _search_method(ctx, method, -1);
	int64_t userid = _search_role(ctx, user, -1);
	int64_t groupid = _search_role(ctx, group, -1);
	sqlite3_stmt *statement;
	const char *sql = "select exp from rules " \
		"where methodid=@METHODID and " \
		"(roleid=@USERID or roleid=@GROUPID or roleid=2);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHODID");
	ret = sqlite3_bind_int(statement, index, methodid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@GROUPID");
	ret = sqlite3_bind_int(statement, index, groupid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	userfilter_dbg("select exp from rules " \
			"where methodid=%ld and " \
			"(roleid=%ld or roleid=%ld or roleid=2);",
			methodid, userid, groupid);
	ret = EREJECT;
	int step = sqlite3_step(statement);
	while (step == SQLITE_ROW)
	{
		int i = 0;
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			const unsigned char *value = NULL;
			value = sqlite3_column_text(statement, i);
			userfilter_dbg("=> %s", value);
			if (!ctx->cmp(ctx, (const char *)value, user, group, home, uri))
			{
				ret = ESUCCESS;
				break;
			}
		}
		step = sqlite3_step(statement);
	}
	if (step != SQLITE_DONE && ret != ESUCCESS)
		err("userfilter: request %d %s", ret, sqlite3_errmsg(ctx->db));
	sqlite3_finalize(statement);
	return ret;
}

static int64_t _insert_field(_mod_userfilter_t *ctx, int table, const char *value, int length)
{
	int64_t ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql[] = {
		"insert into methods (name) values(@VALUE);",
		"insert into roles (name) values(@VALUE);"
	};
	ret = sqlite3_prepare_v2(ctx->db, sql[table], -1, &statement, NULL);
	if (ret != SQLITE_OK) {
		err("%s(%d) %ld: %s\n%s", __FUNCTION__, __LINE__, ret, sql[table], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	int index;
	index = sqlite3_bind_parameter_index(statement, "@VALUE");
	ret = sqlite3_bind_text(statement, index, value, length, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		err("%s(%d) %ld: %s\n%s", __FUNCTION__, __LINE__, ret, sql[table], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	int step = sqlite3_step(statement);
	if (step == SQLITE_DONE)
	{
		ret = sqlite3_last_insert_rowid(ctx->db);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _insert_rule(_mod_userfilter_t *ctx, int64_t methodid, int64_t roleid, const char *exp, int length)
{
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "insert into rules (exp,methodid,roleid) values(@EXP,@METHODID,@ROLEID);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHODID");
	ret = sqlite3_bind_int(statement, index, methodid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@ROLEID");
	ret = sqlite3_bind_int(statement, index, roleid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@EXP");
	ret = sqlite3_bind_text(statement, index, exp, length, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	userfilter_dbg("userfilter: insert into rules (exp,methodid,roleid) values(%s,%ld,%ld);",
		exp, methodid, roleid);
	int step = sqlite3_step(statement);
	if (step == SQLITE_DONE)
	{
		ret = ESUCCESS;
	}
	else
		err("userfilter: error on %s", sqlite3_expanded_sql(statement));

	sqlite3_finalize(statement);
	return ret;
}

static int _delete_rule(_mod_userfilter_t *ctx, int64_t id)
{
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "delete from rules where rowid=@ID";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@ID");
	ret = sqlite3_bind_int(statement, index, id);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int step = sqlite3_step(statement);
	sqlite3_finalize(statement);
	return (step == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static int _jsonifyrule(_mod_userfilter_t *ctx, int64_t id, http_message_t *response)
{
	
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "select methods.name as \"mehtod\", roles.name as \"role\", exp as \"pathexp\", rules.rowid as \"id\" " \
				"from rules " \
				"inner join methods on methods.id = rules.methodid " \
				"inner join roles on roles.id = rules.roleid ;";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int step = sqlite3_step(statement);
	int j = 1;
	while (step == SQLITE_ROW)
	{
		if (j != id)
		{
			step = sqlite3_step(statement);
			j++;
			continue;
		}
		int i = 0;
		const unsigned char *field;
		httpmessage_appendcontent(response, "{\"method\":\"", -1);
		field = sqlite3_column_text(statement, i);
		if (field)
			httpmessage_appendcontent(response, (const char *)field, -1);
		httpmessage_appendcontent(response, "\",\"role\":\"", -1);
		i++;
		field = sqlite3_column_text(statement, i);
		if (field)
			httpmessage_appendcontent(response, (const char *)field, -1);
		httpmessage_appendcontent(response, "\",\"pathexp\":\"", -1);
		i++;
		field = sqlite3_column_text(statement, i);
		if (field)
			httpmessage_appendcontent(response, (const char *)field, -1);
		httpmessage_appendcontent(response, "\",\"id\":\"", -1);
		i++;
		field = sqlite3_column_text(statement, i);
		if (field)
			httpmessage_appendcontent(response, (const char *)field, -1);
		httpmessage_appendcontent(response, "\"}", -1);
		ret = ECONTINUE;
		break;
	}
	if (step == SQLITE_DONE)
		ret = ESUCCESS;
	sqlite3_finalize(statement);
	return ret;
}

static int userfilter_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_userfilter_t *ctx = (_mod_userfilter_t *)arg;
	const mod_userfilter_t *config = ctx->config;
	int ret = ESUCCESS;
	const char *uri = httpmessage_REQUEST(request,"uri");
	const char *method = httpmessage_REQUEST(request, "method");
	const char *user = auth_info(request, STRING_REF(str_user));
	if (user == NULL)
		user = str_anonymous;

	if (utils_searchexp(uri, config->allow, NULL) == ESUCCESS)
	{
		/**
		 * this path is always allowed
		 */
		userfilter_dbg("userfilter: forward to allowed path %s", config->allow);
		ret = EREJECT;
	}
	else if (_request(ctx, method, user,
				auth_info(request, STRING_REF(str_group)),
				auth_info(request, STRING_REF(str_home)),
				uri) == 0)
	{
		ret = EREJECT;
	}
	else
	{
		warn("userfilter: role %s forbidden for %s", user, uri);
		if (user == str_anonymous)
			httpmessage_result(response, RESULT_401);
		else
#if defined RESULT_403
			httpmessage_result(response, RESULT_403);
#else
			httpmessage_result(response, RESULT_400);
#endif
		ret = ESUCCESS;
	}
	return ret;
}

static int64_t _parsequery(_mod_userfilter_t *ctx, http_message_t *request, int ifield)
{
	string_t fields[] = {
		{STRING_REF("method")},
		{STRING_REF("role")},
	};

	if (ifield >= sizeof(fields) / sizeof(string_t))
		return EREJECT;

	const char *value = NULL;
	size_t length = httpmessage_parameter(request, fields[ifield].data, &value);

	if (value == NULL)
	{
		err("userfilter: %.*s empty", (int)fields[ifield].length - 1, fields[ifield].data);
		return EREJECT;
	}

	int64_t id = _search_field(ctx, ifield, value, length);
	if (id == EREJECT)
		id = _insert_field(ctx, ifield, value, length);
	if (id == EREJECT)
		err("userfilter: %.*s %s refused", (int)fields[ifield].length - 1, fields[ifield].data, value);
	return id;
}

static int _userfilter_append(_mod_userfilter_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	int64_t methodid = _parsequery(ctx, request, 0);
	int64_t roleid = _parsequery(ctx, request, 1);
	const char *value = NULL;
	size_t length = httpmessage_parameter(request, "pathexp", &value);
	if (length > 0 && methodid != EREJECT && roleid != EREJECT)
	{
		char *decode = utils_urldecode(value, length);
		if (decode != NULL)
			ret = _insert_rule(ctx, methodid, roleid, decode, -1);
		free(decode);
	}
	if (ret != ESUCCESS)
	{
		err("userfilter: insert in db: %s", sqlite3_errmsg(ctx->db));
		httpmessage_result(response, RESULT_400);
	}
	else
	{
		warn("userfilter: insert %s", value);
#if defined RESULT_204
		httpmessage_result(response, RESULT_204);
#endif
	}
	return ESUCCESS;
}

static int _userfilter_remove(_mod_userfilter_t *ctx, const char *rest, http_message_t *response)
{
	int ret = EREJECT;
	while(rest[0] == '/') rest++;
	int64_t id = strtol(rest, NULL, 10);
	if (id > 0)
	{
		ret = _delete_rule(ctx, id);
	}
	if (ret != ESUCCESS)
	{
		err("userfilter: delete in db: %s", sqlite3_errmsg(ctx->db));
		httpmessage_result(response, RESULT_400);
	}
	else
	{
		warn("userfilter: delete %s", rest);
#if defined RESULT_204
		httpmessage_result(response, RESULT_204);
#endif
	}
	return ESUCCESS;
}

static int _userfilter_get(_mod_userfilter_t *ctx, http_message_t *response)
{
	int ret = EREJECT;
	if (ctx->line == 0)
	{
		httpmessage_addcontent(response, str_mime_textjson, NULL, -1);
		httpmessage_appendcontent(response, "[", -1);
	}
	else
		httpmessage_addcontent(response, NULL, "", -1);
	ctx->line++;
	ret = _jsonifyrule(ctx, ctx->line, response);
	if (ret != ECONTINUE)
	{
		httpmessage_appendcontent(response, "{}]", -1);
		ctx->line = -1;
		ret = ECONTINUE;
	}
	else
		httpmessage_appendcontent(response, ",", -1);
	return ret;
}

static int rootgenerator_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_userfilter_t *ctx = (_mod_userfilter_t *)arg;
	int ret = EREJECT;
	const char *rest = NULL;
	const char *uri = httpmessage_REQUEST(request,"uri");

	userfilter_dbg("userfilter: search %s", ctx->config->configuri);
	if (!utils_searchexp(uri, ctx->config->configuri, &rest))
	{
		userfilter_dbg("userfilter: filter configuration %s", uri);
		userfilter_dbg("userfilter: rest %s", rest);
		const char *method = httpmessage_REQUEST(request, "method");
		if (!strcmp(method, str_put))
		{
			ret = _userfilter_append(ctx, request, response);
		}
		else if (!strcmp(method, str_delete) && rest != NULL)
		{
			ret = _userfilter_remove(ctx, rest, response);
		}
		else if (!strcmp(method, str_get) && ctx->line > -1)
		{
			ret = _userfilter_get(ctx, response);
		}
		else if (ctx->line == -1)
		{
			httpclient_shutdown(httpmessage_client(request));
			return ESUCCESS;
		}
		else
		{
			warn("userfilter: reject method %s", method);
#if defined RESULT_405
			httpmessage_result(response, RESULT_405);
#else
			httpmessage_result(response, RESULT_400);
#endif
			ret = ESUCCESS;
		}
	}

	return ret;
}

static int mod_userfilter_createdb(const char *dbname, const char *superuser, const char *regexp)
{
	sqlite3 *db = NULL;

	if (sqlite3_open_v2(dbname, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		err("userfilter: db %s not generated", dbname);
		return EREJECT;
	}

	const char *query[] = {
		"create table methods (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
		"insert into methods (name) values(\"GET\");",
		"insert into methods (name) values(\"POST\");",
		"insert into methods (name) values(\"PUT\");",
		"insert into methods (name) values(\"DELETE\");",
		"insert into methods (name) values(\"HEAD\");",
		"create table roles (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
		"insert into roles (id, name) values(0, @SUPERUSER);",
		"insert into roles (id, name) values(1, \"anonymous\");",
		"insert into roles (id, name) values(2, \"*\");",
#ifdef DEBUG
		"insert into roles (id, name) values(3, \"users\");",
#endif
		"insert into roles (id, name) values(4, \"reapproving\");",
		"create table rules (\"exp\" TEXT NOT NULL, \"methodid\" INTEGER NOT NULL,\"roleid\" INTEGER NOT NULL, FOREIGN KEY (methodid) REFERENCES methods(id) ON UPDATE SET NULL, FOREIGN KEY (roleid) REFERENCES roles(id) ON UPDATE SET NULL);",
		/// set rights for superuser role
		"insert into rules (exp,methodid,roleid) values(\"^/*\",(select id from methods where name=\"GET\"),0);",
		"insert into rules (exp,methodid,roleid) values(@CONFIGURI,(select id from methods where name=\"PUT\"),0);",
		"insert into rules (exp,methodid,roleid) values(@CONFIGURI,(select id from methods where name=\"DELETE\"),0);",
#ifdef DEBUG
		"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt*\",(select id from methods where name=\"GET\"),0);",
		"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt*\",(select id from methods where name=\"POST\"),0);",
		"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt*\",(select id from methods where name=\"PUT\"),0);",
		"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt*\",(select id from methods where name=\"DELETE\"),0);",
		"insert into rules (exp,methodid,roleid) values(\"^/%g/%u/*\",(select id from methods where name=\"GET\"),3);",
		"insert into rules (exp,methodid,roleid) values(\"^/trust/*\",(select id from methods where name=\"GET\"),1);",
		"insert into rules (exp,methodid,roleid) values(\"^/signup*\",(select id from methods where name=\"GET\"),4);",
		"insert into rules (exp,methodid,roleid) values(\"^/private/*\",(select id from methods where name=\"GET\"),3);",
#endif
		NULL,
	};

	int ret = EREJECT;
	for (int i = 0; query[i] != NULL; i++)
	{
		sqlite3_stmt *statement;
		ret = sqlite3_prepare_v2(db, query[i], -1, &statement, NULL);
		if (ret != SQLITE_OK) {
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, query[i], sqlite3_errmsg(db));
			return EREJECT;
		}

		int index;
		index = sqlite3_bind_parameter_index(statement, "@SUPERUSER");
		if (index > 0)
			ret = sqlite3_bind_text(statement, index, superuser, -1, SQLITE_STATIC);
		if (ret != SQLITE_OK) {
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, query[i], sqlite3_errmsg(db));
			sqlite3_finalize(statement);
			return EREJECT;
		}

		index = sqlite3_bind_parameter_index(statement, "@CONFIGURI");
		if (index > 0)
			ret = sqlite3_bind_text(statement, index, regexp, -1, SQLITE_STATIC);
		if (ret != SQLITE_OK) {
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, query[i], sqlite3_errmsg(db));
			sqlite3_finalize(statement);
			return EREJECT;
		}

		ret = sqlite3_step(statement);
		sqlite3_finalize(statement);
		if (ret != SQLITE_OK && ret != SQLITE_DONE)
		{
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, query[i], sqlite3_errmsg(db));
			ret = EREJECT;
			break;
		}
		else
			ret = ESUCCESS;
	}
	sqlite3_close(db);
	chmod(dbname, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP);
	return ret;
}

#ifdef FILE_CONFIG
static void *userfilter_config(config_setting_t *iterator, server_t *UNUSED(server))
{
	mod_userfilter_t *modconfig = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *config = config_setting_get_member(iterator, "userfilter");
#else
	const config_setting_t *config = config_setting_lookup(iterator, "userfilter");
#endif
	if (config)
	{
		const char *configuri = NULL;
		config_setting_lookup_string(config, "configuri", &configuri);
		if (configuri == NULL || configuri[0] == '\0')
			config_setting_lookup_string(config, "urlpath", &configuri);
		if (configuri == NULL || configuri[0] == '\0')
			configuri = NULL;
		else if (configuri[0] != '^')
		{
			err("userfilter: \"uripath\" configuration field must be a regexp and begin with ^");
			return NULL;
		}

		const char *dbname = NULL;
		config_setting_lookup_string(config, "dbname", &dbname);
		if (dbname == NULL || dbname[0] == '\0')
			dbname = str_userfilterpath;

		const char *superuser = NULL;
		config_setting_lookup_string(config, "superuser", &superuser);
		if (superuser == NULL || superuser[0] == '\0')
			superuser = str_superuser;

		/// test that db not existing and configurable
		if (access(dbname, R_OK) &&
			configuri &&
			mod_userfilter_createdb(dbname, superuser, configuri) != ESUCCESS)
		{
			err("userfilter: impossible to initialize the DB");
			return NULL;
		}

		modconfig = calloc(1, sizeof(*modconfig));
		config_setting_lookup_string(config, "allow", &modconfig->allow);
		modconfig->configuri = configuri;
		modconfig->dbname = dbname;
		modconfig->superuser = superuser;
	}
	return modconfig;
}
#else
mod_userfilter_t g_userfilter_config =
{
	.superuser = "root",
	.configuri = "/auth/filter",
	.dbname = str_userfilterpath,
};

static void *userfilter_config(void *iterator, server_t *server)
{
	/// test that db not existing and configurable
	if (access(g_userfilter_config.dbname, R_OK) &&
		mod_userfilter_createdb(g_userfilter_config.dbname,
					str_superuser,
					g_userfilter_config.configuri) != ESUCCESS)
	{
		err("userfilter: impossible to initialize the DB");
		return NULL;
	}
	return &g_userfilter_config;
}
#endif

void *mod_userfilter_create(http_server_t *server, void *arg)
{
	mod_userfilter_t *config = (mod_userfilter_t *)arg;
	if (config == NULL || config->dbname == NULL)
		return NULL;

	sqlite3 *db = NULL;

	if (sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		err("userfilter: database not found %s", config->dbname);
		return NULL;
	}
	dbg("userfilter: DB storage on %s", config->dbname);

	_mod_userfilter_t *mod = calloc(1, sizeof(*mod));
	mod->config = config;
	mod->cmp = &_exp_cmp;
	mod->db = db;
	httpserver_addmethod(server, METHOD(str_put), MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmethod(server, METHOD(str_delete), MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addconnector(server, userfilter_connector, mod, \
			CONNECTOR_DOCFILTER, str_userfilter);
	if (config->configuri != NULL)
		httpserver_addconnector(server, rootgenerator_connector, mod, \
				CONNECTOR_DOCUMENT, str_userfilter);

	return mod;
}

void mod_userfilter_destroy(void *arg)
{
	_mod_userfilter_t *mod = (_mod_userfilter_t *)arg;
	sqlite3_close(mod->db);
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	free(arg);
}

const module_t mod_userfilter =
{
	.name = str_userfilter,
	.configure = (module_configure_t)&userfilter_config,
	.create = (module_create_t)&mod_userfilter_create,
	.destroy = &mod_userfilter_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_userfilter")));
#endif
