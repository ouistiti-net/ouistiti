/*****************************************************************************
 * authz_file.c: Check Authentication on passwd file
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

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_file.h"


#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_file_config_s authz_file_config_t;
typedef struct authz_file_s authz_file_t;
struct authz_file_s
{
	authz_file_config_t *config;
	char *storage;
	string_t user;
	string_t passwd;
	string_t group;
	string_t home;
#ifdef FILE_MMAP
	char *map;
	int map_size;
	int fd;
#endif
};

struct authz_file_config_s
{
	const char *path;
};

#ifdef FILE_CONFIG
void *authz_file_config(const config_setting_t *configauth)
{
	authz_file_config_t *authz_config = NULL;
	const char *path = NULL;

	config_setting_lookup_string(configauth, "file", &path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	return authz_config;
}
#endif

static void *authz_file_create(http_server_t *UNUSED(server), void *arg)
{
	authz_file_t *ctx = NULL;
	authz_file_config_t *config = (authz_file_config_t *)arg;

#ifdef FILE_MMAP
	struct stat sb;
	int fd = open(config->path, O_RDONLY);
	if (fd == -1)
	{
		err("authz file open error: %s", strerror(errno));
		return NULL;
	}
	if (fstat(fd, &sb) == -1)
	{
		err("authz file access error: %s", strerror(errno));
		close(fd);
		return NULL;
	}

	char *addr = mmap(NULL, sb.st_size, PROT_READ,
				MAP_PRIVATE, fd, 0);
	if (addr != MAP_FAILED)
	{
#endif
		ctx = calloc(1, sizeof(*ctx));
		ctx->config = config;
#ifndef FILE_MMAP
		ctx->storage = calloc(1, MAXLENGTH + 1);
#else
		ctx->map = addr;
		ctx->map_size = sb.st_size;
		ctx->fd = fd;
	}
	else
	{
		err("authz file map error: %s", strerror(errno));
	}
#endif
	dbg("auth: authentication file storage on %s", config->path);
	return ctx;
}

static int _authz_file_parsestring(char *string, int length,
			string_t *puser,
			string_t *ppasswd,
			string_t *pgroup,
			string_t *phome)
{
	char *endline = strchr(string, '\n');
	if (endline != NULL)
		endline[0] = '\0';
	else
		endline = string + length;

	string_t *setters[4] = {puser, ppasswd, pgroup, phome};

	puser->data = string;
	for (int current = 0; current < (sizeof(setters) / sizeof(string_t*)) - 1; current++)
	{
		setters[current + 1]->data = strchr(setters[current]->data, ':');
		if (setters[current + 1]->data)
		{
			setters[current]->length = setters[current + 1]->data - setters[current]->data;
			setters[current + 1]->data += 1;
		}
		else
		{
			setters[current + 1]->data = endline;
			setters[current]->length = endline - setters[current]->data;
		}
	}
	return 0;
}

static int authz_file_passwd(void *arg, const char *user, const char **passwd)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	const authz_file_config_t *config = ctx->config;

#ifdef FILE_MMAP
	char *line;
	line = strstr(ctx->map, user);
	if (line)
	{
		size_t len = 0;
		const char *end = strchr(line, '\n');
		if (end)
			len = end - line;
		else
			len = strlen(line);
		len = (len > MAXLENGTH)?MAXLENGTH:len;

		end = strchr(line, ':');
		if (end == NULL)
			end = line + 1;
		if (!strncmp(line, user, end - line))
		{
			_authz_file_parsestring(line, len, &ctx->user, &ctx->passwd, &ctx->group, &ctx->home);
			*passwd = ctx->passwd.data;
			return ctx->passwd.length;
		}
	}
#else
	FILE *file = fopen(config->path, "r");
	while(file && !feof(file))
	{
		size_t len = 0;
		memset(ctx->storage, 0, MAXLENGTH);
		if (fgets(ctx->storage, MAXLENGTH, file) == NULL)
			break;
		const char *end = strchr(ctx->storage, ':');
		if (end == NULL)
			continue;
		len = end - ctx->storage;
		if (!strncmp(user, ctx->storage, len))
		{
			// storage is MAXLENGTH + 1 length and the last byte is always 0
			int linelen = strlen(ctx->storage);
			_authz_file_parsestring(ctx->storage, linelen, &ctx->user, &ctx->passwd, &ctx->group, &ctx->home);
			fclose(file);
			*passwd = ctx->passwd.data;
			return ctx->passwd.length;
		}
	}
	if (file) fclose(file);
#endif
	return 0;
}

static int _authz_file_checkpasswd(authz_file_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;

	const char *checkpasswd = NULL;
	authz_file_passwd(ctx, user, &checkpasswd);
	if (checkpasswd != NULL)
	{
		string_t userstr = {0};
		string_store(&userstr, user, -1);
		string_t passwdstr = {0};
		string_store(&passwdstr, passwd, -1);
		if (authz_checkpasswd(checkpasswd, &userstr, NULL,  &passwdstr) == ESUCCESS)
			return 1;
	}
	else
		err("auth: user %s not found in file", user);
	return ret;
}

static const char *authz_file_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_file_t *ctx = (authz_file_t *)arg;

	if (user != NULL && passwd != NULL && _authz_file_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static int authz_file_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_file_t *ctx = (const authz_file_t *)arg;

	cb(cbarg, STRING_REF(str_user), STRING_INFO(ctx->user));
	if (!strcmp(ctx->user.data, str_anonymous))
		cb(cbarg, STRING_REF(str_group), STRING_REF(str_anonymous));
	else if (ctx->group.data && ctx->group.length > 0)
		cb(cbarg, STRING_REF(str_group), STRING_INFO(ctx->group));
	else
		cb(cbarg, STRING_REF(str_group), STRING_REF("users"));
	if (ctx->home.data && ctx->home.length > 0)
		cb(cbarg, STRING_REF(str_home), STRING_INFO(ctx->home));
	cb(cbarg, STRING_REF(str_status), STRING_REF(str_status_activated));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));

	return ESUCCESS;
}

static void authz_file_destroy(void *arg)
{
	authz_file_t *ctx = (authz_file_t *)arg;

#ifdef FILE_MMAP
	munmap(ctx->map, ctx->map_size);
	close(ctx->fd);
#else
	free(ctx->storage);
#endif
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_file_rules =
{
	.create = &authz_file_create,
	.check = &authz_file_check,
	.passwd = &authz_file_passwd,
	.setsession = &authz_file_setsession,
	.destroy = &authz_file_destroy,
};
