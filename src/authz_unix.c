/*****************************************************************************
 * authz_unix.c: Check Authentication on passwd file
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
#include <shadow.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <crypt.h>
#include <time.h>

#include "../compliant.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_unix.h"

#define auth_dbg(...)

#define USE_PASSWD_R
//#define FILE_MMAP
#define MAXLENGTH 255

#ifdef USE_REENTRANT
# ifdef CRYPT_DATA_RESERVED_SIZE
#  define USE_CRYPT_R
# endif
# ifdef NSS_BUFLEN_GROUP
#  define USE_GROUP_R
# endif
# ifdef NSS_BUFLEN_PASSWD
#  define USE_PASSWD_R
# endif
#endif

#ifdef HAVE_PWD

typedef struct authz_file_config_s authz_file_config_t;
struct authz_file_config_s
{
	const char *path;
};

typedef struct authz_unix_s authz_unix_t;
struct authz_unix_s
{
	authz_file_config_t *config;
	struct passwd pwstore;
	char passwd[NSS_BUFLEN_PASSWD];
	string_t status;
};

#ifdef FILE_CONFIG
void *authz_unix_config(const config_setting_t *configauth)
{
	authz_file_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "file", (const char **)&path);
	if (path != NULL && path[0] != '0' && strstr(path, "shadow"))
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	return authz_config;
}
#endif

static void *authz_unix_create(http_server_t *UNUSED(server), void *arg)
{
	authz_unix_t *ctx = NULL;
	authz_file_config_t *config = (authz_file_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	return ctx;
}

static struct spwd *_authz_getspnam(authz_unix_t *ctx, const char *user, struct spwd *spwdstore, char *shadow, int shadowlen)
{
	struct spwd *spasswd;
#ifdef USE_PASSWD_R
	getspnam_r(user, spwdstore, shadow, shadowlen, &spasswd);
#else
	spasswd = getspnam(user);
	memcpy(shadow, spasswd->, shadowlen);
	spwdstore->sp_pwdp = shadow;
	spwdstore->sp_expire = 0;
#endif
	return spasswd;
}

static int _authz_unix_checkpasswd(authz_unix_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	string_t status = STRING_DCL(str_status_activated);
	struct passwd *pw = NULL;
	struct spwd spwdstore;
	char shadow[NSS_BUFLEN_PASSWD];

#ifdef USE_PASSWD_R
	getpwnam_r(user, &ctx->pwstore, ctx->passwd, sizeof(ctx->passwd), &pw);
#else
	pw = getpwnam(user);
#endif
	if (passwd && pw)
	{
		const char *cryptpasswd = pw->pw_passwd;
		/* get the shadow password if possible */

		if (!strcmp(cryptpasswd, "x"))
		{
			uid_t uid;
			uid = geteuid();
			/**
			 * change user to root to request shadow file to the system
			 */
			if (seteuid(0) < 0)
				warn("not enought rights to change user to root");
			struct spwd *spasswd = _authz_getspnam(ctx, user, &spwdstore, shadow, sizeof(shadow));
			/**
			 * enable again the user
			 */
			if (seteuid(uid) < 0)
				warn("not enought rights to change user");
			if (spasswd && (spasswd->sp_expire > 0) &&
				(spasswd->sp_expire < (time(NULL) / (60 * 60 * 24))))
			{
				warn("authz: user %s password expired", user);
				return 0;
			}
			if (spasswd && spasswd->sp_pwdp)
			{
				cryptpasswd = spasswd->sp_pwdp;
			}
			else
			{
				warn("authz unix: unaccessible user");
				return 0;
			}
			time_t now = time(NULL);
			long day = now / (60 * 60 * 24);
			if (spasswd->sp_max > 0 && day > (spasswd->sp_lstchg + spasswd->sp_max))
				string_store(&status, STRING_REF(str_status_reapproving));
			if (spasswd->sp_expire > 0 && day > spasswd->sp_expire)
				string_store(&status, STRING_REF(str_status_repudiated));
		}
		else if (cryptpasswd[0] == '!')
		{
			string_store(&status, STRING_REF(str_status_repudiated));
			cryptpasswd += 1;
		}

		const char *testpasswd = NULL;
#ifdef USE_CRYPT_R
		struct crypt_data crdata = {0};
		testpasswd = crypt_r(passwd, cryptpasswd, &crdata);
#else
		testpasswd = crypt(passwd, cryptpasswd);
#endif
		if (testpasswd && !strcmp(testpasswd, cryptpasswd))
		{
			ret = 1;
			string_store(&ctx->status, STRING_INFO(status));
		}
		else
		{
			auth_dbg("authz unix: passwd error");
		}
	}
	else
	{
		auth_dbg("authz unix: user %s not found", user);
	}
	return ret;
}

static const char *authz_unix_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;

	if (user != NULL && passwd != NULL && _authz_unix_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static int authz_unix_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_unix_t *ctx = (const authz_unix_t *)arg;

	cb(cbarg, STRING_REF(str_user), ctx->pwstore.pw_name, -1);

	struct group *grp = NULL;
	struct group grpstorage;
	char group[NSS_BUFLEN_PASSWD];
#ifdef USE_GROUP_R
	getgrgid_r(ctx->pwstore.pw_gid, &grpstorage, group, sizeof(group), &grp);
#else
	grp = getgrgid(ctx->pwstore.pw_gid);
#endif
	if (grp != NULL)
		cb(cbarg, STRING_REF(str_group), grp->gr_name, -1);
	cb(cbarg, STRING_REF(str_home), ctx->pwstore.pw_dir, -1);
	cb(cbarg, STRING_REF(str_status), STRING_INFO(ctx->status));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));
	return ESUCCESS;
}

static void authz_unix_destroy(void *arg)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_unix_rules =
{
	.create = &authz_unix_create,
	.check = &authz_unix_check,
	.passwd = NULL,
	.setsession = &authz_unix_setsession,
	.destroy = &authz_unix_destroy,
};
#endif
